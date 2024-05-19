from secrets import token_bytes
from base64 import b64decode, b64encode

import argon2.exceptions
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash


# ALL OUTPUT AND INPUT MUST BE ON BASE64 ENCODING
# Except argon2id hash
# The default string bytes conversion is utf-8


def hash_argon2id(string: str) -> str:
    """
    Hash a string using the Argon2id algorithm.

    :param string: The string to hash.
    :return: The hashed string.
    """
    ph = PasswordHasher()
    return ph.hash(string)


def verify_hash_argon2id(hashed_string: str, string: str) -> bool:
    """
    Verify a string against a hashed string using the Argon2id algorithm.

    :param hashed_string: The hashed string.
    :param string: The string to verify.
    :return: True if the string matches the hashed string, False otherwise.
    """
    ph = PasswordHasher()
    try:
        return ph.verify(hashed_string, string)
    except argon2.exceptions.VerifyMismatchError:
        return False


def hash_sha256(string: str, encoding: str = 'utf-8') -> str:
    """
    Hash a string using the SHA-256 algorithm.

    :param string: The string to hash.
    :param encoding: The encoding to use to encode the string.
    :return: The hashed string.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(string.encode(encoding))
    return digest.finalize().hex()


def derive_key_pbkdf2hmac(string: str, b64_salt: str = None, encoding: str = 'utf-8') -> tuple[str, str]:
    """
    Derive a 256bit key and a 128bit salt (used to generate the key) using the PBKDF2HMAC algorithm. It will output
    both key and salt in Base64 encoding.

    :param string: The string to derive the key from.
    :param b64_salt: The salt to use for the derivation. If None, a new salt is generated.
    :param encoding: The encoding to use to encode the string.
    :return: A tuple of the derived key and the salt, both base64 encoded.
    """
    if b64_salt is None:
        b64_salt = token_bytes(16)
    else:
        b64_salt = b64decode(b64_salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # The size is 256bit, to be used as AES-GCM key / main key
        salt=b64_salt,
        iterations=500_000,
    )
    key = kdf.derive(string.encode(encoding))

    return b64encode(key).decode(encoding), b64encode(b64_salt).decode(
        encoding)  # Outputs Base64, decode first before use


def generate_aesgcm_key(encoding: str = 'utf-8') -> str:
    """
    Generate a 256bit key for AES-256-GCM encryption. It will output the key in Base64 Encoding

    :param encoding: The encoding to use to encode the key.
    :return: The generated key, base64 encoded.
    """
    key = token_bytes(32)
    return b64encode(key).decode(encoding)


def encrypt_aesgcm(b64_key: str, string: str, tag: str, encoding: str = 'utf-8') -> tuple[str, str]:
    """
    Encrypt a string using AES-256-GCM. It takes the key in only Base64 encoding, and output the ciphertext and nonce
    in Base64 encoding.

    :param b64_key: The key to use for the encryption, base64 encoded.
    :param string: The string to encrypt.
    :param tag: The tag could be a user_id for main key and chat key, or "SYS" for system use.
    :param encoding: The encoding to use to encode the string and the ID, defaults to utf-8.
    :return: A tuple of the ciphertext and the nonce used for the encryption, both base64 encoded.
    """
    b64_key = b64decode(b64_key)
    text = string.encode(encoding)
    aad = tag.encode(encoding)
    nonce = token_bytes(12)

    aesgcm = AESGCM(b64_key)
    ciphertext = aesgcm.encrypt(nonce, text, aad)

    return b64encode(ciphertext).decode(encoding), b64encode(nonce).decode(encoding)


def decrypt_aesgcm(b64_key: str, b64_nonce: str, b64_ciphertext: str, tag: str, encoding: str = 'utf-8') -> str:
    """
    Decrypt a ciphertext using AES-256-GCM. The key and nonce should be Base64 encoded, and it will output the plaintext
    as normal string.

    :param b64_key: The key to use for the decryption, base64 encoded.
    :param b64_nonce: The nonce used for the encryption, base64 encoded.
    :param b64_ciphertext: The ciphertext to decrypt, base64 encoded.
    :param tag: The tag could be a user_id for main key and chat key, or "SYS" for system use.
    :param encoding: The encoding to use to encode the ID and decode the plaintext, defaults to utf-8.
    :return: The decrypted string.
    """
    b64_key = b64decode(b64_key)
    b64_nonce = b64decode(b64_nonce)
    b64_ciphertext = b64decode(b64_ciphertext)
    aad = tag.encode(encoding)

    aesgcm = AESGCM(b64_key)
    plaintext = aesgcm.decrypt(b64_nonce, b64_ciphertext, aad)

    return plaintext.decode(encoding)


def generate_ecc_keys(encoding: str = 'utf-8') -> tuple[str, str]:
    """
        Generate a pair of ECC keys (private and public) using the SECP384R1 curve.
        The keys are serialized and encoded in Base64.

        :param encoding: The encoding to use for the Base64 encoding, defaults to utf-8.
        :return: A tuple of the private key and the public key, both Base64 encoded.
    """
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # The private key will be encrypted before storage later
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return b64encode(private_pem).decode(encoding), b64encode(public_pem).decode(encoding)  # Base64 then string utf-8


def exchange_key_ecc(serialized_own_private_key: str, serialized_partner_public_key, encoding: str = 'utf-8') -> str:
    """
        Perform a key exchange using ECC and derive a shared secret key.
        The input keys must be serialized and Base64 encoded.
        The output shared key is also Base64 encoded.

        :param serialized_own_private_key: The user's private key, serialized and Base64 encoded.
        :param serialized_partner_public_key: The partner's public key, serialized and Base64 encoded.
        :param encoding: The encoding to use for the Base64 encoding, defaults to utf-8.
        :return: The shared secret key, Base64 encoded.
    """
    own_private_key = serialization.load_pem_private_key(
        b64decode(serialized_own_private_key),
        password=None  # INFO: The private key will be encrypted before storage later
    )
    partner_public_key = serialization.load_pem_public_key(
        b64decode(serialized_partner_public_key)
    )

    shared_key = own_private_key.exchange(ec.ECDH(), partner_public_key)
    return _derive_key_conkatkdf(shared_key, encoding)


def _derive_key_conkatkdf(shared_key: bytes, encoding: str) -> str:
    """
        Derive a 256-bit key from a shared secret key using the ConcatKDFHash function.
        The output key is Base64 encoded.

        :param shared_key: The shared secret key.
        :param encoding: The encoding to use for the Base64 encoding, defaults to utf-8.
        :return: The derived key, Base64 encoded.
    """
    # Internal function
    other_info = b'Key Exchange'
    cdkf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,  # The size is 256bit, to be used as AES-GCM key / chat key
        otherinfo=other_info
    )

    key = cdkf.derive(shared_key)
    return b64encode(key).decode(encoding)


if __name__ == "__main__":
    ...
