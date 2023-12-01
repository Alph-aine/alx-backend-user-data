#!/usr/bin/env python3
'''Encrypts passwords'''

import bcrypt


def hash_password(password: str) -> bytes:
    '''Returns a salted, hash password'''
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt(14))

    return hashed
