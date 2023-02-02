#!/usr/bin/env python3
"""Password encryption"""

import bcrypt


def hash_password(password: str) -> bytes:
    """returns salted, hashed password, which is a byte string"""
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """validates that provided password matches the hashed password"""
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        return True
    return False
