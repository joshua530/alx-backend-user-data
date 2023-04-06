#!/usr/bin/env python3
"""
Basic API authentication module

Implements methods defined in Auth
"""

from api.v1.auth.auth import Auth
from base64 import b64decode
from models.user import User
from typing import Tuple, TypeVar


class BasicAuth(Auth):
    """ Basic Authentication implementation """

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retrieves User instance for request """

        auth_header = self.authorization_header(request)
        header_value = self.extract_base64_authorization_header(auth_header)
        decoded_value = self.decode_base64_authorization_header(header_value)
        user_data = self.extract_user_credentials(decoded_value)
        return self.user_object_from_credentials(user_data[0], user_data[1])

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """ base64 Decodes authorization header value """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_base64_authorization_header(self, authorization_header: str)\
            -> str:
        """ Fetches authorization header value(minus the Basic part) """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if "Basic " not in authorization_header:
            return None

        return authorization_header.split("Basic ", 1)[1]

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """ Fetches email and password from decoded authorization header """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None

        return decoded_base64_authorization_header.split(":", 1)[0], \
            decoded_base64_authorization_header.split(":", 1)[1]

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ Fetches User based on email and password """
        if user_email is None or user_pwd is None:
            return None
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        try:
            search_users = User.search({'email': user_email})
        except Exception:
            return None

        for user in search_users:
            if user.is_valid_password(user_pwd):
                return user
            else:
                return None
