#!/usr/bin/env python3
"""
Session authentication with expiration module for the API.
"""

from os import getenv
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """ Deals with expiration of sessions """

    def __init__(self):
        """ init method """

        self.session_duration = 0

        if int(getenv('SESSION_DURATION')):
            self.session_duration = int(getenv('SESSION_DURATION'))

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Returns User ID based on Session ID """

        if session_id is None or isinstance(session_id, str) is False:
            return None

        session_dict = self.user_id_by_session_id.get(session_id)
        if session_dict is None or 'created_at' not in session_dict:
            return None

        if self.session_duration <= 0:
            return session_dict.get('user_id')
        created_time = session_dict.get('created_at')
        session_elapsed = timedelta(seconds=self.session_duration)

        if created_time + session_elapsed < datetime.now():
            return None
        else:
            return session_dict.get('user_id')

    def create_session(self, user_id: str = None) -> str:
        """ Creates a Session ID for user_id """

        try:
            session_id = super().create_session(user_id)
        except Exception:
            return None

        session_dictionary = {
            'user_id': user_id,
            'created_at': datetime.now()
        }
        self.user_id_by_session_id[session_id] = session_dictionary

        return session_id
