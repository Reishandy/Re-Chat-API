z[//]: # (TODO)

# Re Chat API

## Description

ReChat is a secure, real-time chat application built with Python and FastAPI. It leverages modern cryptographic
techniques to ensure the privacy and security of your conversations.

## Features

- **User Registration and Login:** Users can register with their email and password. Passwords are securely hashed using
  the
  Argon2id algorithm before being stored.

- **End-to-End Encryption:** All chat messages are encrypted using AES-256-GCM, ensuring that only the sender and the
  recipient can read them.

- **ECC Key Exchange:** ReChat uses Elliptic Curve Cryptography (ECC) for secure key exchange, allowing users to
  establish a
  shared secret key for conversation.

- **Real-Time Messaging:** Leveraging WebSockets, ReChat provides real-time, bidirectional communication between users.

- **Contact Management:** Users can add other users to their contact list and retrieve their contact details.

- **Session Management:** ReChat handles user sessions, including token generation and validation, ensuring secure user
  authentication.

- **Database Integration:** ReChat uses MongoDB for storing and retrieving user data, messages, and contact information.

- **Automatic Session Cleanup:** Expired user sessions are automatically cleaned up from the database.

## Installation

This project requires Python and pip. Install the dependencies with:

```bash
pip install -r requirements.txt
```

Then set up .env variables

- MONGO_URL=_your MongoDB url_
- DATABASE_NAME=_your database name_
- APP_KEY=_your 32-bit aes gcm key in base64 encoding_
- TOKEN_SECRET=_your random secure 32-bit hex token_

## Usage

export .env
```bash
export $(grep -v '^#' .env | xargs -d '\n')
```
run with fastapi
```bash
fastapi run main.py --reload
```
run with uvicorn
```bash
uvicorn main:app --reload
```

## License

[MIT](LICENSE)

### Please note that this application is a demonstration of secure chat application concepts and should not be used as-is for production purposes.