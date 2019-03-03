# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""


class NoSuchUserException(Exception):
    """No User exists with the given username."""


class UserAlreadyExistsException(Exception):
    """A User already exists with the given username.

        Please try another username.

    """


class NoSuchResourceException(Exception):
    """No Resource exists with the given hostname."""


class ResourceAlreadyExistsException(Exception):
    """A Resource already exists with the given hostname."""


class EncryptionFailedException(Exception):
    """Failed to encrypt the given message"""


class DecryptionFailedException(Exception):
    """Failed to decrypt the given message"""


class CorruptedDataException(Exception):
    """Base64 Encoded data is corrupted."""


class InvalidOperationException(Exception):
    """Given operation is invalid or not supported."""
