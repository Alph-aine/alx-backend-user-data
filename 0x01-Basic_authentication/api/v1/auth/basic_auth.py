#!/usr/bin/env python3
'''Basic authentication'''

from base64 import b64decode
from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    pass
