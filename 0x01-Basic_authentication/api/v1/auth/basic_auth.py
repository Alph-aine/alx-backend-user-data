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

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        '''decodes the base64 part'''
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            encoded = base64_authorization_header.encode("utf-8")
            decoded64 = b64decode(encoded)
            decoded = decoded64.decode("utf-8")

            return decoded
        except BaseException:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        '''Get user credentials'''
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None

        credentials = decoded_base64_authorization_header.split(':', 1)
        return credentials[0], credentials[1]
