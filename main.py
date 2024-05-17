from typing import Annotated
from contextlib import asynccontextmanager
from os import environ

from pydantic import BaseModel, Field, EmailStr
from fastapi import FastAPI, status, Response, Body, HTTPException
from pymongo import MongoClient
from pymongo.database import Database

import app.database as db_handler

# === DATABASE CONNECTION ===
CLIENT: MongoClient
DB: Database


@asynccontextmanager
async def lifespan(app: FastAPI):
    global CLIENT, DB

    # Connect to the Database
    mongo_url = environ['MONGO_URL']
    database_name = environ['DATABASE_NAME']

    CLIENT = MongoClient(mongo_url)
    DB = CLIENT[database_name]  # TODO: Replace with actual database

    yield

    # Clean up the connection
    CLIENT.close()


app = FastAPI(lifespan=lifespan)


# === MODELS ===
class Registration(BaseModel):
    email: EmailStr = Field(..., description="The email of the user.")
    name: str = Field(..., description="The name of the user.", examples=['Username'])
    password: str = Field(
        ..., min_length=8, description="The password of the user. Minimum length is 8 characters.",
        examples=['SECURE_password_0']
    )


class Logging(BaseModel):
    email_or_uuid: str = Field(
        ..., description="Email or UUID of the user.",
        pattern=r'^([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$|'
                r'^RE_CHAT_[0-9A-F]{8}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{12}$',
        examples=['user@example.com', 'RE_CHAT_00000000_0000_0000_0000_000000000000']
    )

    password: str = Field(
        ..., min_length=8, description="The password of the user.",
        examples=['SECURE_password_0']
    )


# === ENDPOINTS ===
# REGISTER ENDPOINT
@app.post(
    '/register',
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {
            "description": "Registration success",
            "content": {
                "application/json": {
                    "example": {"detail": "User successfully registered"}
                }
            }
        },
        400: {
            "description": "Registration failed",
            "content": {
                "application/json": {
                    "example": {"detail": "Registration failed due to XYZ reason"}
                }
            }
        }})
async def register(
        registration_data: Annotated[Registration, Body(
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
# TODO: Dont forget input validation, make it Annotated
#   validate login: password, and email or uuid
#   return login: ok, error
# TODO: Session storage in mongodb
# TODO: Create login endpoint that returns the access and refresh token

# REFRESH ENDPOINT
# TODO: Create refresh PUT endpoint

# TODO: Token
#   make access and refresh and issues when successfully logged in
#   access handler, every access to protected it will be checked if it match then if expired.
#       if token does not match return unauthorized, if expired generate a new one and return unauthorized
#   refresh endpoint to refresh the access token, will send a new access token (server stored) if refresh token match
#       if not user will be logged out
#   ALL PROTECTED ENDPOINT NEEDS TO VERIFY ACCESS TOKEN VIA REQUEST HEADER

# TODO: Event startup and shutdown
# TODO: Database event startup and shutdown
# TODO: Session cleaner
