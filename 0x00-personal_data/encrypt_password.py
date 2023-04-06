#!/usr/bin/env python3
"""Password encryption

creates and verifies passwords using bcrypt algorithm
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """salts, then hashes password which is then returned"""
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """validates that provided password matches the hashed password

    Return:
        True if matches, False if not
    """
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        return True
    return False
