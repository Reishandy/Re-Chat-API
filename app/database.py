from re import match
from uuid import uuid4
from datetime import datetime, UTC

import pymongo.errors
from pymongo import ReturnDocument
from pymongo.database import Database

from app.security import hash_argon2id, verify_hash_argon2id, generate_ecc_keys, derive_key_pbkdf2hmac, \
    encrypt_aesgcm, decrypt_aesgcm, exchange_key_ecc, hash_sha256


async def register(database: Database, email: str, name: str, password: str) -> None:
    """
        Register a new user in the database.

        This function will create a new user with the given email, name, and password.
        The password will be hashed using the Argon2id algorithm before being stored.
        The function will also generate a pair of ECC keys for the user.

        If the email is already in use, a ValueError will be raised.
        If the generated UUID is already in use, a RuntimeError will be raised.

        :param database: The database to use.
        :param email: The email of the user.
        :param name: The name of the user.
        :param password: The password of the user.
        :return: None
        :raises ValueError: If email and uuid invalid.
    """
    # INFO: Does not raise any error if the user registered successfully
    # Additional validation
    if not bool(match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email)):
        raise ValueError('Email is not valid')

    # Check if the email is taken
    users_col = database['usersDb']
    if users_col.find_one({'email': email}):
        raise ValueError('Email is already taken')

    # Prepare the data
    uuid = 'RE_CHAT_' + str(uuid4()).upper().replace('-', '_')
    hashed_password = hash_argon2id(password)
    private_pem, public_pem = generate_ecc_keys()

    # Encrypt private ecc key
    key, salt = derive_key_pbkdf2hmac(password)
    private_pem_encrypted, private_pem_nonce = encrypt_aesgcm(key, private_pem, uuid)

    # Store general user info on users collection
    try:
        result = users_col.insert_one({
            '_id': uuid,
            'email': email,
            'name': name,
            'hashed_password': hashed_password,
            'main_key_salt': salt,
            'public_key': public_pem,
            'private_key_encrypted': private_pem_encrypted,
            'private_key_nonce': private_pem_nonce,
            'contacts': []
        })
        if not result.acknowledged:
            raise RuntimeError('User insert operation was not acknowledged')
    except pymongo.errors.DuplicateKeyError:
        raise ValueError('UUID already taken: UNLUCKY')


async def login(database: Database, uuid_or_email: str, password: str) -> tuple[str, str]:
    """
        Login a user in the database.

        This function will authenticate a user with the given uuid_or_email and password.
        The function will also decrypt the user's private key.

        If the uuid_or_email or password is incorrect, a ValueError will be raised.

        :param database: The database to use.
        :param uuid_or_email: The uuid or email of the user.
        :param password: The password of the user.
        :return: A tuple of the UUID and main key.
        :raises ValueError: If wrong credentials.
    """
    # Validate email or uuid
    if bool(match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', uuid_or_email)):
        email_mode = True
    elif bool(match(r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}$', uuid_or_email)):
        email_mode = False
    else:
        raise ValueError('Invalid format: not an Email nor UUID')

    # Check if exists from collection list on email or uuid
    users_col = database['usersDb']
    if email_mode:
        result = users_col.find_one({'email': uuid_or_email}, {'_id': 1, 'hashed_password': 1, 'main_key_salt': 1})
        if result is None:
            raise ValueError('Unknown Email')
        uuid = result['_id']
    else:
        result = users_col.find_one({'_id': uuid_or_email}, {'hashed_password': 1, 'main_key_salt': 1})
        if result is None:
            raise ValueError('Unknown UUID')
        uuid = uuid_or_email

    # Retrieve is_keys info
    hashed_password = result['hashed_password']
    main_key_salt = result['main_key_salt']

    # Verify password
    if not verify_hash_argon2id(hashed_password, password):
        raise ValueError('Incorrect password')

    # Get main key
    key = derive_key_pbkdf2hmac(password, main_key_salt)[0]

    # Returns main key and private key
    return uuid, key


async def get_info(database: Database, uuid: str) -> tuple[str, str, str]:
    """
    Retrieve user information from the database.

    This function queries the database for a user with the given UUID and returns the user's UUID, email, and name.
    If the user does not exist, a ValueError is raised.

    :param database: The database to use.
    :param uuid: The UUID of the user.
    :return: A tuple containing the user's UUID, email, and name.
    :raises ValueError: If the user does not exist.
    """
    # WARNING: Only call this function in protected and verified endpoint
    # Query the id
    users_col = database['usersDb']
    result = users_col.find_one({'_id': uuid}, {'email': 1, 'name': 1})
    if result is None:
        raise ValueError('User does not exists')

    # Returns the info
    return uuid, result['email'], result['name']


async def add_contact(database: Database, own_uuid: str, partner_uuid: str, own_main_key: str) -> None:
    """
    Add a new contact to the user's contact list.

    This function will add a new contact to the user's contact list in the database.
    The function will also generate a shared key for the user and the new contact.

    If the user or the contact does not exist, a ValueError will be raised.

    :param database: The database to use.
    :param own_uuid: The UUID of the user.
    :param partner_uuid: The UUID of the new contact.
    :param own_main_key: The main key of the user.
    :return: None
    :raises ValueError: If the user or the contact does not exist.
    """
    # WARNING: Only call this function in protected and verified endpoint
    # Get own private key
    users_col = database['usersDb']
    own_result = users_col.find_one({
        '_id': own_uuid}, {'private_key_encrypted': 1, 'private_key_nonce': 1, 'contacts': 1})
    if own_result is None:
        raise ValueError('User does not exists')

    # Check if partner already in contact
    for contact in own_result['contacts']:
        if partner_uuid == contact['partner_uuid']:
            raise ValueError('Already in contact')

    # Get partner public key
    partner_result = users_col.find_one({'_id': partner_uuid}, {'public_key': 1})
    public_key = partner_result['public_key']

    # Decrypt own private key
    private_key_encrypted = own_result['private_key_encrypted']
    private_key_nonce = own_result['private_key_nonce']
    private_key = decrypt_aesgcm(own_main_key, private_key_nonce, private_key_encrypted, own_uuid)

    # Do a key exchange, and encrypt it
    shared_key = exchange_key_ecc(private_key, public_key)
    shared_key_encrypted, shared_key_nonce = encrypt_aesgcm(own_main_key, shared_key, own_uuid)

    # Create a new shared chat collection (only the name)
    combined_uuid = ''.join(sorted([own_uuid, partner_uuid]))
    shared_collection = 'RE_CHAT_' + hash_sha256(combined_uuid) + '_Db'

    # Insert details into own contact
    result = users_col.update_one({'_id': own_uuid}, {'$push': {'contacts': {
        'partner_uuid': partner_uuid,
        'shared_collection': shared_collection,
        'shared_key_encrypted': shared_key_encrypted,
        'shared_key_nonce': shared_key_nonce
    }}})
    if not result.acknowledged:
        raise RuntimeError('Contact insert operation was not acknowledged')


async def get_contacts(database: Database, uuid: str) -> list[dict[str, str]]:
    """
    Retrieve the user's contact list from the database.

    This function queries the database for a user with the given UUID and returns the user's contact list.
    If the user does not exist, a ValueError is raised.

    :param database: The database to use.
    :param uuid: The UUID of the user.
    :return: A list containing the UUIDs of the user's contacts.
    :raises ValueError: If the user does not exist.
    """
    # WARNING: Only call this function in protected and verified endpoint
    # INFO: To get all contacts, returns a list of UUID only
    # Query with id
    users_col = database['usersDb']
    result = users_col.find_one({'_id': uuid}, {'contacts': 1})
    if result is None:
        raise ValueError('User does not exists')

    # Get list of partner_uuids
    partner_uuids = [contact['partner_uuid'] for contact in result['contacts']]

    # Query for all partners at once
    partners = users_col.find({'_id': {'$in': partner_uuids}}, {'name': 1})

    # Build the response
    contacts_parsed = [{'uuid': partner['_id'], 'name': partner['name']} for partner in partners]

    return contacts_parsed


async def get_contact_details(database: Database, own_uuid: str, partner_uuid: str, own_main_key: str) \
        -> tuple[str, str, str]:
    """
    Retrieve the details of a specific contact from the user's contact list.

    This function queries the database for a user with the given UUID and a contact with the given partner UUID.
    It returns the contact's UUID, the shared collection, and the shared key.
    If the user or the contact does not exist, a ValueError is raised.

    :param database: The database to use.
    :param own_uuid: The UUID of the user.
    :param partner_uuid: The UUID of the contact.
    :param own_main_key: The main key of the user.
    :return: A tuple containing the contact's UUID, the shared collection, and the shared key.
    :raises ValueError: If the user or the contact does not exist.
    """
    # WARNING: Only call this function in protected and verified endpoint
    # INFO: To get a single contact details, return uuid, shared collection, and shared key. Use for sending message
    # Query with id
    users_col = database['usersDb']
    result = users_col.find_one({'_id': own_uuid}, {'contacts': 1})
    if result is None:
        raise ValueError('User does not exists')

    # Get partner details
    contacts = result['contacts']
    shared_collection = None
    shared_key_encrypted = None
    shared_key_nonce = None
    for contact in contacts:
        if partner_uuid != contact['partner_uuid']:
            continue

        shared_collection = contact['shared_collection']
        shared_key_encrypted = contact['shared_key_encrypted']
        shared_key_nonce = contact['shared_key_nonce']

    # Check if contact exist
    if shared_collection is None:
        raise ValueError('Contact does not exist')

    # Decrypt the shared key
    shared_key = decrypt_aesgcm(own_main_key, shared_key_nonce, shared_key_encrypted, own_uuid)

    # Returns the details
    return partner_uuid, shared_collection, shared_key


async def _get_next_sequence(database: Database, collection_name: str) -> int:
    """
        Get the next sequence number for a given collection.

        This function queries the 'countersDb' collection in the database for a document with the given collection name
        and increments the 'seq' field of the document. The updated 'seq' value is then returned.

        :param database: The database to use.
        :param collection_name: The name of the collection for which to get the next sequence number.
        :return: The next sequence number for the given collection.
    """
    counters_col = database['countersDb']
    counter = counters_col.find_one_and_update(
        {'_id': collection_name},
        {'$inc': {'seq': 1}},
        return_document=ReturnDocument.AFTER,
        upsert=True
    )
    return counter['seq']


async def add_message(database: Database, uuid: str, shared_key: str, shared_db_name: str, message: str) -> None:
    """
    Add a new message to a shared chat collection.

    This function encrypts the given message with the shared key and inserts a new document into the shared chat
    collection in the database. The document contains the encrypted message, the UUID of the sender, the current
    timestamp, and a read status flag set to False.

    :param database: The database to use.
    :param uuid: The UUID of the sender.
    :param shared_key: The shared key to use for encrypting the message.
    :param shared_db_name: The name of the shared chat collection.
    :param message: The message to add.
    :return: None
    """
    # WARNING: Only call this function in protected and verified endpoint
    # Prepare the data
    message_encrypted, message_nonce = encrypt_aesgcm(shared_key, message, uuid)
    date_time = datetime.now(UTC).strftime('%d/%m/%Y %H:%M:%S')
    message_id = await _get_next_sequence(database, shared_db_name)

    # Insert into shared chat db
    shared_db_col = database[shared_db_name]
    result = shared_db_col.insert_one({
        '_id': message_id,
        'from': uuid,
        'message_encrypted': message_encrypted,
        'message_nonce': message_nonce,
        'timestamp': date_time,
        'read_status': False
    })
    if not result.acknowledged:
        raise RuntimeError('Message insert operation was not acknowledged')


async def get_messages(database: Database, shared_db_name: str, shared_key: str, own_uuid: str, partner_uuid: str,
                       num_messages: int | None = None, from_id: int | None = None) -> list[dict[str, str]]:
    """
    Retrieve messages from a shared chat collection.

    This function queries the shared chat collection in the database for messages. If a 'from_id' is provided, it
    retrieves messages with an '_id' less than 'from_id'. If a 'num_messages' is provided, it limits the number of
    messages retrieved. The messages are sorted in descending order by '_id'. The function decrypts the messages
    with the shared key and returns a list of dictionaries, each containing the decrypted message, the UUID of the
    sender, the timestamp, and the read status.

    :param database: The database to use.
    :param shared_db_name: The name of the shared chat collection.
    :param shared_key: The shared key to use for decrypting the messages.
    :param own_uuid: The UUID of the user retrieving the messages.
    :param partner_uuid: The UUID of the partner.
    :param num_messages: The maximum number of messages to retrieve.
    :param from_id: The '_id' from which to start retrieving messages.
    :return: A list of dictionaries, each containing a decrypted message, the UUID of the sender, the timestamp, and
             the read status.
    """
    # WARNING: Only call this function in protected and verified endpoint
    # Get messages
    shared_db_col = database[shared_db_name]
    if from_id is None and num_messages is None:
        result = shared_db_col.find().sort({'_id': -1})
    elif from_id is None and num_messages:
        result = shared_db_col.find().limit(num_messages).sort({'_id': -1})
    else:
        result = shared_db_col.find({'_id': {'$lte': from_id}}).sort({'_id': -1}).limit(num_messages)

    # Parse the result
    messages = []
    result_list = list(result)
    for result in result_list:
        # Prepare some data
        message_id = result['_id']
        message_nonce = result['message_nonce']
        message_encrypted = result['message_encrypted']

        # Determine if the message is from own or partner
        if own_uuid == result['from']:
            from_uuid = own_uuid
            read_status = result['read_status']
        else:
            from_uuid = partner_uuid
            await update_read_status(database, shared_db_name, message_id, True)
            read_status = True

        # Decrypt the message
        message = decrypt_aesgcm(shared_key, message_nonce, message_encrypted, from_uuid)

        # Add to the list, parsed
        messages.append({
            '_id': message_id,
            'from_uuid': from_uuid,
            'message': message,
            'timestamp': result['timestamp'],
            'read_status': read_status
        })

    return messages


async def update_read_status(database: Database, shared_db_name: str, message_id: int, read_status: bool) -> None:
    """
    Update the read status of a message in a shared chat collection.

    This function updates the 'read_status' field of the document with the given 'message_id' in the shared chat
    collection in the database. If the update operation is not acknowledged, a RuntimeError is raised.

    :param database: The database to use.
    :param shared_db_name: The name of the shared chat collection.
    :param message_id: The id of the message to update.
    :param read_status: The new read status.
    :return: None
    :raises RuntimeError: If the update operation is not acknowledged.
    """
    # WARNING: Only call this function in protected and verified endpoint
    # Get the shared database collection
    shared_db_col = database[shared_db_name]

    # Update the read status of the message with the given id
    result = shared_db_col.update_one({'_id': message_id}, {'$set': {'read_status': read_status}})

    if not result.acknowledged:
        raise RuntimeError('Update operation was not acknowledged')


if __name__ == '__main__':
    ...
