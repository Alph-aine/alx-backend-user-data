#!/usr/bin/env python3
'''Auth Class Implemntation'''

from flask import request
from typing import List, TypeVar


class Auth:
    '''Auth class'''

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''checks for paths that needs authentication'''
        if not path or path is None:
            return True
        if not excluded_paths or excluded_paths is None:
            return True
        if not path.endswith('/'):
            path += '/'

        if path not in excluded_paths:
            return True

        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        '''DocDoc'''
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''DOcDOc'''
        return None
