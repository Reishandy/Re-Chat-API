import time
from datetime import datetime, timedelta, UTC

import pymongo.errors
import jwt.exceptions
from jwt import encode, decode
from pymongo.database import Database

from app.security import encrypt_aesgcm, decrypt_aesgcm


# TODO: CREATE DOCSTRING AND UNITTEST

def generate_token(token_secret: str, uuid: str, is_refresh_token: bool = False, access_expiry_seconds: int = 3600,
                   refresh_expiry_seconds: int = 259200, hash_algorithm: str = 'HS256') -> str:
    # Defaults expiry for access is 1 hour while refresh is 3 days
    exp = datetime.now(UTC) + timedelta(seconds=refresh_expiry_seconds if is_refresh_token else access_expiry_seconds)
    return encode({'uuid': uuid, 'exp': exp}, token_secret, algorithm=hash_algorithm)


async def add_session(database: Database, app_key: str, token_secret: str, uuid: str, key: str,
                      access_token: str | None = None, refresh_token: str | None = None) -> tuple[str, str]:
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


async def validate_token(database: Database, token_secret: str, access_token: str | None = None,
                         refresh_token: str | None = None, is_refresh: bool = False,
                         hash_algorithm: str = 'HS256') -> bool:
    # If token invalid, get a refresh or remove session
    if access_token is None and refresh_token is None:
        raise ValueError('Both should not be None')

    # Decode token, either refresh or access
    try:
        token = decode(refresh_token if is_refresh else access_token, token_secret, algorithms=hash_algorithm)
    except jwt.exceptions.ExpiredSignatureError:
        raise ValueError('Token expired')

    # Check validity
    uuid = token['uuid']
    session_col = database['sessionsDb']
    result = session_col.find_one({'_id': uuid})
    if result is None:
        raise RuntimeError('Session does not exists')

    if is_refresh:
        if result['refresh_token'] != refresh_token:
            raise ValueError('Refresh_token does not match')
    else:
        if result['access_token'] != access_token:
            raise ValueError('Access_token does not match')

    return True  # Valid token


async def update_token(database: Database, token_secret: str, uuid: str, access_token: str | None = None) -> str:
    # Only updates access token, should only be used inside refresh endpoint
    access_token = generate_token(token_secret, uuid) if access_token is None else access_token

    session_col = database['sessionsDb']
    result = session_col.update_one({'_id': uuid}, {'$set': {'access_token': access_token}})
    if result.matched_count == 0:
        raise ValueError('Session does not exist')
    if result.modified_count == 0:
        raise RuntimeError('Unable to update session')

    return access_token


# TODO: Retrieve main key
# TODO: Remove user session
# TODO: Clean expired session

if __name__ == '__main__':
    from os import environ
    from pymongo import MongoClient
    from app.database import login
    from asyncio import run
    from time import sleep

    mongo_url = environ['MONGO_URL']
    db_name = environ['DATABASE_NAME']
    app_key = environ['APP_KEY']
    secret = environ['TOKEN_SECRET']

    client = MongoClient(mongo_url)
    db = client[db_name]

    db['sessionsDb'].drop()

    uuid, key = run(login(db, 'a@a.a', 'a'))
    access, refresh = run(add_session(db, app_key, secret, uuid, key))
    print(run(validate_token(db, secret, access_token=access)))
    print(run(validate_token(db, secret, is_refresh=True, refresh_token=refresh)))

    sleep(5)

    new_token = run(update_token(db, secret, uuid, generate_token(secret, uuid, access_expiry_seconds=10)))
    try:
        print(run(validate_token(db, secret, access_token=access)))
    except ValueError as e:
        print(e)

    print(run(validate_token(db, secret, access_token=new_token)))
    sleep(10)
    try:
        print(run(validate_token(db, secret, access_token=new_token)))
    except ValueError as e:
        print(e)

    client.close()
