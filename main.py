from asyncio import sleep, create_task, CancelledError, gather
from contextlib import asynccontextmanager
from logging import info, basicConfig, INFO
from os import environ
from re import match
from typing import Annotated

from fastapi import FastAPI, status, Body, HTTPException, Header, Depends, Path, WebSocket, WebSocketDisconnect, \
    WebSocketException
from pydantic import BaseModel, Field, EmailStr, field_validator
from pymongo import MongoClient
from pymongo.database import Database
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorClient

import app.database as db_handler
import app.session as ss_manager

# === GLOBAL ===
CLIENT: MongoClient
DB: Database
DB_MOTOR: AsyncIOMotorDatabase
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
async def clean_session_periodically(database: Database, token_secret: str) -> None:
    while True:
        await sleep(3600)  # INFO: Ran every hour
        await ss_manager.clean_session(database, token_secret)


async def validate_session(access_token: str = Header(), uuid: str = Header()) -> str:
    global DB, TOKEN_SECRET

    # Validate headers format
    if not match(r'^[A-Za-z0-9-_]+.[A-Za-z0-9-_]+.[A-Za-z0-9-_]+$', access_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid access token')
    if not match(r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}', uuid):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid UUID')

    try:
        if await ss_manager.validate_token(DB, TOKEN_SECRET, uuid, access_token=access_token):
            return uuid
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


# === FAST API ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    global CLIENT, DB, TOKEN_SECRET, APP_KEY, DB_MOTOR
    # INFO: Must set up environment variables
    mongo_url = environ['MONGO_URL']
    database_name = environ['DATABASE_NAME']  # INFO: Replace with actual database in .env
    # INFO: Should be 256bit (32Bytes) secure random hex string.
    TOKEN_SECRET = environ['TOKEN_SECRET']
    # INFO: Should be 256bit (32Bytes) secure random encoded in Base64.
    #       Can be generated from app.security.generate_aesgcm_key()
    APP_KEY = environ['APP_KEY']

    # Connect to the Database
    CLIENT = MongoClient(mongo_url)
    DB = CLIENT[database_name]

    # Connect using motor client
    client_motor = AsyncIOMotorClient(mongo_url)
    DB_MOTOR = client_motor[database_name]

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
                    'example': {
                        'uuid': 'Users UUID',
                        'access_token': 'Access token',
                        'refresh_token': 'Refresh token'
                    }
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
        await ss_manager.remove_session(DB, uuid)  # INFO: Not inside a protected endpoint, but verified

    # Add to session
    access_token, refresh_token = await ss_manager.add_session(DB, APP_KEY, TOKEN_SECRET, uuid, key)

    # Issue access and refresh token
    return {'uuid': uuid, 'access_token': access_token, 'refresh_token': refresh_token}


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
        404: {
            'description': 'Session not found',
            'content': {
                'application/json': {
                    'example': {'detail': 'Session not found'}
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
    try:
        if await ss_manager.remove_session(DB, current_user):
            return {'detail': 'User logged out successfully'}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# REFRESH ENDPOINT
@app.post(
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
async def refresh(refresh_token: str = Header(), uuid: str = Header()) -> dict[str, str]:
    global DB, TOKEN_SECRET

    # Validate headers format
    if not match(r'^[A-Za-z0-9-_]+.[A-Za-z0-9-_]+.[A-Za-z0-9-_]+$', refresh_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid refresh token')
    if not match(r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}', uuid):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid UUID')

    # Confusing times man....
    try:
        if not await ss_manager.validate_token(DB, TOKEN_SECRET, uuid, refresh_token=refresh_token, is_refresh=True):
            HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')

        # Issue a new token
        new_access_token = await ss_manager.update_token(DB, TOKEN_SECRET, uuid)
        return {'access_token': new_access_token}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


# GET INFO ENDPOINT
@app.get(
    "/user/{user_uuid}",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "examples": {
                        "Get own info": {
                            "value": {
                                "uuid": "RE_CHAT_00000000_0000_0000_0000_000000000000",
                                "email": "user@example.com",
                                "name": "Username"
                            }
                        },
                        "Get other user's info": {
                            "value": {
                                "uuid": "RE_CHAT_00000000_0000_0000_0000_000000000000",
                                "name": "Username"
                            }
                        }
                    }
                }
            }
        },
        404: {
            "description": "Not Found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User does not exist"
                    }
                }
            }
        }})
async def get_user_info(
        user_uuid: str = Path(..., description="The UUID of the user to fetch the info."),
        current_user: str = Depends(validate_session)) -> dict[str, str]:
    global DB

    try:
        user_info = await db_handler.get_info(DB, user_uuid)
        if user_uuid == current_user:
            return {"uuid": user_info[0], "email": user_info[1], "name": user_info[2]}

        return {"uuid": user_info[0], "name": user_info[2]}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ADD CONTACT ENDPOINT
@app.post(
    '/user/{partner_uuid}/add_to_contact',
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {
            'description': 'Contact added successfully',
            'content': {
                'application/json': {
                    'example': {'detail': 'Contact added successfully'}
                }
            }
        },
        400: {
            'description': 'Failed to add contact',
            'content': {
                'application/json': {
                    'example': {'detail': 'Failed to add contact due to XYZ reason'}
                }
            }
        },
        401: {
            'description': 'Authentication problem',
            'content': {
                'application/json': {
                    'example': {'detail': 'Invalid access token'}
                }
            }
        }})
async def add_contact(partner_uuid: str = Path(..., description="The UUID of the contact to add."),
                      current_user: str = Depends(validate_session)) -> dict[str, str]:
    global DB, APP_KEY

    try:
        # Get main key
        main_key = await ss_manager.get_main_key(DB, APP_KEY, current_user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    try:
        # Add to contact
        await db_handler.add_contact(DB, current_user, partner_uuid, main_key)
        return {'detail': 'Contact added successfully'}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# GET CONTACTS ENDPOINT
@app.get(
    '/get_contacts',
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            'description': 'Contacts retrieved successfully',
            'content': {
                'application/json': {
                    'example': {'contacts': [{'uuid': 'UUID1', 'name': 'name1'}, {'uuid': 'UUID2', 'name': 'name2'}]}
                }
            }
        },
        401: {
            'description': 'Authentication problem',
            'content': {
                'application/json': {
                    'example': {'detail': 'Invalid access token'}
                }
            }
        }})
async def get_contacts(current_user: str = Depends(validate_session)) -> dict[str, list[dict[str, str]]]:
    global DB

    try:
        contacts = await db_handler.get_contacts(DB, current_user)
        return {'contacts': contacts}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# MESSAGING HELPER FUNCTION
basicConfig(level=INFO)


async def validate_session_websocket(access_token: str, uuid: str) -> str:
    global DB, TOKEN_SECRET

    # Validate headers format
    if not match(r'^[A-Za-z0-9-_]+.[A-Za-z0-9-_]+.[A-Za-z0-9-_]+$', access_token):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason='Invalid access token')
    if not match(r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}', uuid):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason='Invalid UUID')

    try:
        if await ss_manager.validate_token(DB, TOKEN_SECRET, uuid, access_token=access_token):
            return uuid
    except ValueError as e:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason=str(e))


async def receive_message_from_db(websocket: WebSocket, shared_collection: str, shared_key: str,
                                  own_uuid: str, partner_uuid: str) -> None:
    global DB, DB_MOTOR

    # Get pipeline
    shared_col = DB_MOTOR[shared_collection]
    pipeline = [{'$match': {'operationType': 'insert'}}]

    try:
        async with shared_col.watch(pipeline) as stream:
            async for insert_change in stream:
                if insert_change['fullDocument']['from'] == own_uuid:
                    await sleep(0.1)

                msg_id = insert_change['fullDocument']['_id']

                # Run fetch and send
                message = await db_handler.get_messages(DB, shared_collection, shared_key, own_uuid, partner_uuid,
                                                        num_messages=1, from_id=msg_id)
                await websocket.send_text(str(message[0]))
    except WebSocketDisconnect:
        await websocket.close()
        return
    except Exception as e:
        info(str(e))


async def send_message_to_db(websocket: WebSocket, shared_collection: str, shared_key: str, own_uuid: str) -> None:
    global DB

    try:
        while True:
            message = await websocket.receive_text()

            # Add message to database
            await db_handler.add_message(DB, own_uuid, shared_key, shared_collection, message)
    except WebSocketDisconnect:
        await websocket.close()
        return
    except Exception as e:
        info(str(e))


# MESSAGING WEBSOCKET ENDPOINT
@app.websocket('/chat')
async def chat_websocket(websocket: WebSocket) -> None:
    """
    EXPLAIN IN DETAILS HOW THIS WORKS AND WHAT DOES IT NEED.
    :param websocket:
    :return:
    """
    # WARNING: THIS ENDPOINT USES A DIFFERENT MONGODB DRIVER, WHICH IS NOT GOOD. DO NOT DO THIS!!!

    global DB, TOKEN_SECRET, APP_KEY
    await websocket.accept()

    # Get initial data (FORMAT IS 'TOKEN|UUID|PARTNER_UUID')
    credentials = await websocket.receive_text()
    try:
        access_token, uuid, partner_uuid = credentials.split('|')
    except ValueError:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason='Invalid credentials format')

    # Validate session
    r_uuid = await validate_session_websocket(access_token, uuid)
    if r_uuid != uuid:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason='UUID mismatch')

    info(f'{uuid} connection established')

    # Get main key and contact details
    try:
        main_key = await ss_manager.get_main_key(DB, APP_KEY, uuid)
        _, shared_collection, shared_key = await db_handler.get_contact_details(DB, uuid, partner_uuid, main_key)
    except ValueError as e:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason=str(e))

    # Send all messages (temporary)
    messages_initial = await db_handler.get_messages(DB, shared_collection, shared_key, uuid, partner_uuid)
    await websocket.send_text(str(messages_initial))

    # Start receiver and sender thread
    sender_task = create_task(send_message_to_db(websocket, shared_collection, shared_key, uuid))
    receiver_task = create_task(
        receive_message_from_db(websocket, shared_collection, shared_key, uuid, partner_uuid))
    try:
        await gather(sender_task, receiver_task)
    except RuntimeError:
        pass

    info(f'{uuid} connection closed')
