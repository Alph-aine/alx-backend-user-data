#!/usr/bin/env python3
'''Encrypts passwords'''

import bcrypt


def hash_password(password: str) -> bytes:
    '''Returns a salted, hash password'''
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt(14))

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    '''Checks if password and hashed password matches'''
    encoded = password.encode()

    result = bcrypt.checkpw(encoded, hashed_password)
    return result
