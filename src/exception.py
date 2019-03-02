# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""


class NoSuchUserException(Exception):
    """No User exists with the given username."""
    pass


class UserAlreadyExistsException(Exception):
    """A User already exists with the given username.

        Please try another username.

    """
    pass


class NoSuchResourceException(Exception):
    """No Resource exists with the given hostname."""
    pass


class ResourceAlreadyExistsException(Exception):
    """A Resource already exists with the given hostname."""
    pass


class EncryptionFailedException(Exception):
    """Failed to encrypt the given message"""
    pass
