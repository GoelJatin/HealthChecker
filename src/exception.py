# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

class NoSuchUserException(Exception):
    pass


class UserAlreadyExistsException(Exception):
    pass


class NoSuchResourceException(Exception):
    pass


class ResourceAlreadyExistsException(Exception):
    pass


class EncryptionFailedException(Exception):
    pass
