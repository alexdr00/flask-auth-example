from hashlib import sha256, pbkdf2_hmac
from binascii import hexlify
import os


def hash_password(password):
    salt = sha256(os.urandom(60)).hexdigest().encode('ascii')
    password_hash = pbkdf2_hmac(
        'sha512',
        password.encode('utf-8'),
        salt,
        100000
    )

    password_hash = hexlify(password_hash)
    password_hash = (salt + password_hash).decode('ascii')

    return password_hash


def match_passwords(stored_password, provided_password):
    stored_password_salt = stored_password[:64]
    stored_password_hash = stored_password[64:]

    provided_password_hash = pbkdf2_hmac(
        'sha512',
        provided_password.encode('utf-8'),
        stored_password_salt.encode('ascii'),
        100000
    )

    provided_password_hash = hexlify(provided_password_hash).decode('ascii')

    do_passwords_match = provided_password_hash == stored_password_hash

    return do_passwords_match
