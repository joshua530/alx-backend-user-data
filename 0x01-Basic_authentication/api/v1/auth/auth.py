#!/usr/bin/env python3
"""
API authentication module
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """ Authentication base class """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Ascertains API routes require authentication """
        if path is None or not excluded_paths:
            return True
        for i in excluded_paths:
            if i.endswith('*') and path.startswith(i[:-1]):
                return False
            elif i in {path, path + '/'}:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Ascertains Authorization request header is present
        & is not empty """
        if request is None or "Authorization" not in request.headers:
            return None
        else:
            return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """ user placeholder """
        return None
