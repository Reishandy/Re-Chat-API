from typing import Annotated
from contextlib import asynccontextmanager
from os import environ
from asyncio import sleep, create_task, CancelledError
from re import match

from pydantic import BaseModel, Field, EmailStr, field_validator
from fastapi import FastAPI, status, Body, HTTPException, Header, Depends
from pymongo import MongoClient
from pymongo.database import Database

import app.database as db_handler
import app.session as ss_manager

# === GLOBAL ===
CLIENT: MongoClient
DB: Database
TOKEN_SECRET: str
APP_KEY: str


# === MODELS ===
class RegisterModel(BaseModel):
    email: EmailStr = Field(..., description='The email of the user.')
    name: str = Field(..., description='The name of the user.', examples=['Username'])
    password: str = Field(
        ..., min_length=8, description='The password of the user. Minimum length is 8 characters.',
        examples=['SECURE_password_0']
    )


class LoginModel(BaseModel):
    uuid_or_email: str = Field(
        ..., description='UUID or Email of the user.',
        examples=['user@example.com', 'RE_CHAT_00000000_0000_0000_0000_000000000000']
    )

    password: str = Field(
        ..., min_length=8, description='The password of the user.',
        examples=['SECURE_password_0']
    )

    @field_validator('uuid_or_email')
    def uuid_or_email_validator(cls, v):
        pattern = (r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$|'
                   r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}')
        if not match(pattern, v):
            raise ValueError('invalid format: not an Email nor UUID')
        return v


# === HELPER FUNCTION ===
async def clean_session_periodically(database: Database, token_secret: str, ):
    while True:
        await sleep(3600)  # INFO: Ran every hour
        await ss_manager.clean_session(database, token_secret)


async def validate_session(access_token: str = Header(), uuid: str = Header()):
    global DB, TOKEN_SECRET

    # Validate headers format
    if not match(r'^[A-Za-z0-9-_]+.[A-Za-z0-9-_]+.[A-Za-z0-9-_]+$', access_token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid access token')
    if not match(r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}', uuid):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid UUID')

    try:
        if await ss_manager.validate_token(DB, TOKEN_SECRET, access_token=access_token):
            return uuid
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


# === FAST API ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    global CLIENT, DB, TOKEN_SECRET, APP_KEY
    # WARNING: Must set up environment variables
    mongo_url = environ['MONGO_URL']
    database_name = environ['DATABASE_NAME']  # TODO: Replace with actual database in .env
    # INFO: Should be 256bit (32Bytes) secure random hex string.
    TOKEN_SECRET = environ['TOKEN_SECRET']
    # INFO: Should be 256bit (32Bytes) secure random encoded in Base64.
    #       Can be generated from app.security.generate_aesgcm_key()
    APP_KEY = environ['APP_KEY']

    # Connect to the Database
    CLIENT = MongoClient(mongo_url)
    DB = CLIENT[database_name]

    # Clean the session before accepting any requests
    await ss_manager.clean_session(DB, TOKEN_SECRET)

    # Clean expired session periodically
    clean_session_task = create_task(clean_session_periodically(DB, TOKEN_SECRET))

    yield

    # Clean up background task
    clean_session_task.cancel()
    try:
        await clean_session_task
    except CancelledError:
        pass

    # Clean up the connection
    CLIENT.close()


app = FastAPI(lifespan=lifespan)


# === ENDPOINTS ===
# REGISTER ENDPOINT
@app.post(
    '/register',
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {
            'description': 'Registration successful',
            'content': {
                'application/json': {
                    'example': {'detail': 'User added successfully'}
                }
            }
        },
        400: {
            'description': 'Registration failed',
            'content': {
                'application/json': {
                    'example': {'detail': 'Registration failed due to XYZ reason'}
                }
            }
        }})
async def register(
        registration_data: Annotated[RegisterModel, Body(
            title='User Registration details',
            description='Endpoint to register a new user. Requires unused email, name, and password.'
        )]) -> dict[str, str]:
    global DB

    try:
        await db_handler.register(DB, **registration_data.dict())
        return {'detail': 'User added successfully'}
    except ValueError or RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# LOGIN ENDPOINT
@app.post(
    '/login',
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            'description': 'Login successful',
            'content': {
                'application/json': {
                    'example': {'access_token': 'Access token', 'refresh_token': 'Refresh token'}
                }
            }
        },
        401: {
            'description': 'Login failed',
            'content': {
                'application/json': {
                    'example': {'detail': 'Login failed due to invalid credentials'}
                }
            }
        }})
async def login(
        login_data: Annotated[LoginModel, Body(
            title='User credentials',
            description='Endpoint to login and get tokens, requires email or UUID and password.'
        )]) -> dict[str, str]:
    global DB, TOKEN_SECRET, APP_KEY

    # Get uuid and key from login first
    try:
        uuid, key = await db_handler.login(DB, **login_data.dict())
    except ValueError as e:  # Handle invalid credentials
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    # Check if session already exist (with uuid), if yes remove first
    if await ss_manager.check_session_exists(DB, uuid):
        await ss_manager.remove_session(DB, uuid)  # WARNING: Not inside a protected endpoint, but verified

    # Add to session
    access_token, refresh_token = await ss_manager.add_session(DB, APP_KEY, TOKEN_SECRET, uuid, key)

    # Issue access and refresh token
    return {'access_token': access_token, 'refresh_token': refresh_token}


# LOGOUT ENDPOINT
@app.delete(
    '/logout',
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {
            'description': 'Logout successful',
            'content': {
                'application/json': {
                    'example': {'detail': 'User logged out successfully'}
                }
            }
        },
        400: {
            'description': 'Logout failed',
            'content': {
                'application/json': {
                    'example': {'detail': 'Logout failed due XYZ reason'}
                }
            }
        },
        401: {
            'description': 'Authentication problem',
            'content': {
                'application/json': {
                    'example': {'detail': 'Invalid Access Token'}
                }
            }
        }})
async def logout(current_user: str = Depends(validate_session)) -> dict[str, str]:
    global DB

    # INFO: Currently does not handle Runtime error inside remove_session(),
    #       because already handled by validate_session() depend
    if await ss_manager.remove_session(DB, current_user):
        return {'detail': 'User logged out successfully'}


# REFRESH ENDPOINT
@app.get(
    '/refresh',
    description='User should be redirected to the login page if this endpoint returns 401 Unauthorized',
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            'description': 'Refresh successful',
            'content': {
                'application/json': {
                    'example': {'access_token': 'Access token'}
                }
            }
        },
        401: {
            'description': 'Authentication problem',
            'content': {
                'application/json': {
                    'example': {'detail': 'Invalid refresh token'}
                }
            }
        }})
async def refresh(access_token: str = Header(), refresh_token: str = Header(), uuid: str = Header()) -> dict[str, str]:
    global DB, TOKEN_SECRET

    # Validate headers format
    if not match(r'^[A-Za-z0-9-_]+.[A-Za-z0-9-_]+.[A-Za-z0-9-_]+$', access_token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid access token')
    if not match(r'^[A-Za-z0-9-_]+.[A-Za-z0-9-_]+.[A-Za-z0-9-_]+$', refresh_token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid refresh token')
    if not match(r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}', uuid):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid UUID')

    # Confusing times man....
    try:
        if (not await ss_manager.validate_token(DB, TOKEN_SECRET, access_token=access_token) or
                await ss_manager.validate_token(DB, TOKEN_SECRET, refresh_token=refresh_token, is_refresh=True)):
            HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')

        # Issue a new token
        new_access_token = await ss_manager.update_token(DB, TOKEN_SECRET, uuid)
        return {'access_token': new_access_token}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


# TODO: GET INFO ENDPOINT
# TODO: MESSAGING ENDPOINTS

# TODO: Session:
#   Validate access / refresh token
#   Retrieve main key
#   Clean expired session (event async)

# TODO: Token
#   make access and refresh and issues when successfully logged in
#   access handler, every access to protected it will be checked if it match then if expired.
#       if token does not match return unauthorized, if expired generate a new one and return unauthorized
#   refresh endpoint to refresh the access token, will send a new access token (server stored) if refresh token match
#       if not user will be logged out
#   ALL PROTECTED ENDPOINT NEEDS TO VERIFY ACCESS TOKEN VIA REQUEST HEADER

# WARNING: MAKE SURE EVERY CALL TO DATABASE HANDLER AND SESSION MANAGER HAVE AWAIT
