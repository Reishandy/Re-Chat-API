from datetime import datetime, timedelta, UTC

import pymongo.errors
import jwt.exceptions
from jwt import encode, decode
from pymongo.database import Database

from app.security import encrypt_aesgcm, decrypt_aesgcm


def generate_token(token_secret: str, uuid: str, is_refresh_token: bool = False, access_expiry_seconds: int = 3600,
                   refresh_expiry_seconds: int = 259200, hash_algorithm: str = 'HS256') -> str:
    """
        Generate a JWT token. Defaults expiry for access is 1 hour while refresh is 3 days.

        :param token_secret: The secret key used for the token encoding.
        :param uuid: The identifier of the user for whom the token is being generated.
        :param is_refresh_token: A boolean indicating whether the token is a refresh token.
        :param access_expiry_seconds: The number of seconds until the access token expires.
        :param refresh_expiry_seconds: The number of seconds until the refresh token expires.
        :param hash_algorithm: The hashing algorithm to use.
        :return: The generated token.
    """
    now = datetime.now(UTC)
    expiry = timedelta(seconds=refresh_expiry_seconds if is_refresh_token else access_expiry_seconds)
    exp = now + expiry
    return encode({'uuid': uuid, 'exp': exp}, token_secret, algorithm=hash_algorithm)


async def add_session(database: Database, app_key: str, token_secret: str, uuid: str, key: str,
                      access_token: str | None = None, refresh_token: str | None = None) -> tuple[str, str]:
    """
        Add a user session to the database. WARNING: This should be called after login is successfully.

        :param database: The database to use.
        :param app_key: The application key.
        :param token_secret: The secret key used for the token encoding.
        :param uuid: The identifier of the user for whom the session is being added.
        :param key: The user's key.
        :param access_token: The user's access token.
        :param refresh_token: The user's refresh token.
        :return: A tuple containing the access token and the refresh token.
    """
    # Generate access and refresh token
    access_token = generate_token(token_secret, uuid) if access_token is None else access_token
    refresh_token = generate_token(token_secret, uuid, True) if refresh_token is None else refresh_token

    # Encrypt user key with app key
    key_encrypted, key_nonce = encrypt_aesgcm(app_key, key, 'APP')

    # Insert into session
    session_col = database['sessionsDb']
    try:
        result = session_col.insert_one({
            '_id': uuid,
            'key_encrypted': key_encrypted,
            'key_nonce': key_nonce,
            'access_token': access_token,
            'refresh_token': refresh_token
        })
        if not result.acknowledged:
            raise RuntimeError('General insert operation was not acknowledged')
    except pymongo.errors.DuplicateKeyError:
        raise RuntimeError('Session already exist')

    return access_token, refresh_token


async def check_session_exists(database: Database, uuid: str) -> bool:
    """
        Check if a session exists in the database for a given user.

        :param database: The database to use.
        :param uuid: The identifier of the user.
        :return: True if a session exists for the user, False otherwise.
    """
    session_col = database['sessionsDb']
    result = session_col.find_one({'_id': uuid})
    if result is None:
        return False

    return True


async def validate_token(database: Database, token_secret: str, uuid: str, access_token: str | None = None,
                         refresh_token: str | None = None, is_refresh: bool = False,
                         hash_algorithm: str = 'HS256') -> bool:
    """
        Validate a token.

        :param database: The database to use.
        :param token_secret: The secret key used for the token encoding.
        :param uuid: THe uuid of the user.
        :param access_token: The access token to validate.
        :param refresh_token: The refresh token to validate.
        :param is_refresh: A boolean indicating whether the token is a refresh token.
        :param hash_algorithm: The hashing algorithm to use.
        :return: True if the token is valid, False otherwise.
    """
    # INFO: If token invalid, get a refresh or remove session
    if access_token is None and refresh_token is None:
        raise RuntimeError('Both should not be None')

    # Decode token, either refresh or access
    try:
        token = decode(refresh_token if is_refresh else access_token, token_secret, algorithms=hash_algorithm)
    except jwt.exceptions.ExpiredSignatureError:
        raise ValueError('Token expired')
    except jwt.exceptions.DecodeError:
        raise ValueError('Invalid token')

    # Check additional validity
    uuid_token = token['uuid']
    if uuid != uuid_token:
        raise ValueError('UUID mismatch')

    session_col = database['sessionsDb']
    result = session_col.find_one({'_id': uuid})
    if result is None:
        raise ValueError('Session not found')

    if is_refresh:
        if result['refresh_token'] != refresh_token:
            raise ValueError('Invalid refresh token')
    else:
        if result['access_token'] != access_token:
            raise ValueError('Invalid access token')

    return True  # Valid token


async def update_token(database: Database, token_secret: str, uuid: str, access_token: str | None = None) -> str:
    """
        Update a token. Only updates access token, should only be used inside refresh endpoint.
        WARNING: Only call in protected and verified endpoint.

        :param database: The database to use.
        :param token_secret: The secret key used for the token encoding.
        :param uuid: The identifier of the user for whom the token is being updated.
        :param access_token: The new access token.
        :return: The updated token.
    """
    access_token = generate_token(token_secret, uuid) if access_token is None else access_token

    session_col = database['sessionsDb']
    result = session_col.update_one({'_id': uuid}, {'$set': {'access_token': access_token}})
    if result.matched_count == 0:
        raise ValueError('Session does not exists')

    return access_token


async def get_main_key(database: Database, app_key: str, uuid: str) -> str:
    """
        Get the main key for a user from their session. WARNING: Only call in protected and verified endpoint.

        :param database: The database to use.
        :param app_key: The application key.
        :param uuid: The identifier of the user.
        :return: The user's main key.
    """
    session_col = database['sessionsDb']
    result = session_col.find_one({'_id': uuid}, {'key_encrypted': 1, 'key_nonce': 1})
    if result is None:
        raise ValueError('Session does not exists')

    # Get and decrypt
    key_encrypted = result['key_encrypted']
    key_nonce = result['key_nonce']

    return decrypt_aesgcm(app_key, key_nonce, key_encrypted, 'APP')


async def remove_session(database: Database, uuid: str) -> bool:
    """
            Remove a user session from the database. WARNING: Only call in protected and verified endpoint.

            :param database: The database to use.
            :param uuid: The identifier of the user for whom the session is being removed.
            :return: True if the session was removed successfully, False otherwise.
    """
    session_col = database['sessionsDb']
    result = session_col.delete_one({'_id': uuid})
    if not result.acknowledged:
        raise RuntimeError('Session delete operation was not acknowledged')
    if result.deleted_count == 0:
        raise ValueError('Session not found')

    return True


async def clean_session(database: Database, token_secret: str, hash_algorithm: str = 'HS256') -> int:
    """
        Clean expired sessions from the database. Should be run as a periodic background task

        :param database: The database to use.
        :param token_secret: The secret key used for the token encoding.
        :param hash_algorithm: The hashing algorithm to use.
    """
    # INFO: Run as a periodic background task
    print('Running session cleanup...')

    cleaned_up = 0
    session_col = database['sessionsDb']
    results = session_col.find()

    for result in results:
        try:
            decode(result['refresh_token'], token_secret, algorithms=hash_algorithm)
        except jwt.exceptions.ExpiredSignatureError:
            await remove_session(database, result['_id'])
            cleaned_up += 1

    print(f"Cleaned up {cleaned_up} sessions.")
    return cleaned_up


if __name__ == '__main__':
    ...
