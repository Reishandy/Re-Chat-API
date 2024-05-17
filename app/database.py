from re import match
from uuid import uuid4
from os import environ

import pymongo.errors
from pymongo import MongoClient
from pymongo.database import Database

from app.security import (hash_argon2id, verify_hash_argon2id, generate_ecc_keys, derive_key_pbkdf2hmac, encrypt_aesgcm,
                          decrypt_aesgcm)


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
    """
    # comment: does not raise any error if the user registered successfully
    # Validation
    if not bool(match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email)):
        raise ValueError('Email is not valid')
    if password == '':
        raise ValueError('Password is empty')
    if len(password) < 8:
        raise ValueError('Password is too short < 8')

    # Check if the email is taken
    users_col = database['users']
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
            'public_key': public_pem
        })
        if not result.acknowledged:
            raise RuntimeError('General insert operation was not acknowledged')
    except pymongo.errors.DuplicateKeyError:
        raise RuntimeError('UUID already taken: UNLUCKY')

    # Store specific key info
    specific_col = database[uuid]
    result = specific_col.insert_one({
        'is_keys': True,
        'hashed_password': hashed_password,
        'main_key_salt': salt,
        'private_key_encrypted': private_pem_encrypted,
        'private_key_nonce': private_pem_nonce
    })
    if not result.acknowledged:
        raise RuntimeError('Specific insert operation was not acknowledged')


async def login(database: Database, uuid_or_email: str, password: str) -> tuple[str, str]:
    """
        Login a user in the database.

        This function will authenticate a user with the given uuid_or_email and password.
        The function will also decrypt the user's private key.

        If the uuid_or_email or password is incorrect, a ValueError will be raised.

        :param database: The database to use.
        :param uuid_or_email: The uuid or email of the user.
        :param password: The password of the user.
        :return: A tuple of the main key and private key.
    """
    # Validate email or uuid
    if bool(match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', uuid_or_email)):
        email_mode = True
    elif bool(match(r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}$', uuid_or_email)):
        email_mode = False
    else:
        raise ValueError('Invalid format: not and Email nor UUID')

    # Check if exists from collection list on email or uuid
    if email_mode:
        users_col = database['users']
        result = users_col.find_one({'email': uuid_or_email}, {'_id': 1})
        if result is None:
            raise ValueError('Unknown Email')
        uuid = result['_id']
    else:
        col_list = database.list_collection_names()
        if uuid_or_email not in col_list:
            raise ValueError('Unknown UUID')
        uuid = uuid_or_email

    # Retrieve is_keys info
    specific_col = database[uuid]
    keys = specific_col.find_one({'is_keys': True})
    if keys is None:
        raise RuntimeError('This should not happen')

    # Parse result
    hashed_password = keys['hashed_password']
    main_key_salt = keys['main_key_salt']
    private_pem_encrypted = keys['private_key_encrypted']
    private_pem_nonce = keys['private_key_nonce']

    # Verify password
    if not verify_hash_argon2id(hashed_password, password):
        raise ValueError('Incorrect password')

    # Decrypt main key
    key = derive_key_pbkdf2hmac(password, main_key_salt)[0]
    private_pem = decrypt_aesgcm(key, private_pem_nonce, private_pem_encrypted, uuid)

    # Returns main key and private key
    return key, private_pem


if __name__ == '__main__':
    ...
