#!/usr/bin/env python3
'''Basic authentication'''

from base64 import b64decode
from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    '''Basic Authentication class'''
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        '''extract authorization header'''
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None

        plain = authorization_header.split(' ', 1)[1]

        return plain
