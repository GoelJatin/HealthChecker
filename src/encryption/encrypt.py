# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os
import hashlib

from constants import (
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH
)


def encrypt(salt, password):
    """Encodes the password using the given value of **salt** and
        the SHA512 algorithm.

    """
    if not isinstance(password, bytes):
        password = password.encode()

    return hashlib.sha512(password + salt).digest()


class Encrypt:
    """Base class for Encryption and Decryption operations."""

    def _generate_cipher(self):
        """Abstract method to be implemented by Child classes, to create the cipher objects."""
        raise NotImplementedError()

    def reset(self):
        """Destroy the previous RSA keys and cipher objects,
            and then generate fresh RSA keys and cipher objects again.

        """
        self.destroy()
        self._generate_cipher()

    @staticmethod
    def destroy():
        """Remove the RSA key files, and delete the cipher objects."""
        os.unlink(PRIVATE_KEY_PATH)
        os.unlink(PUBLIC_KEY_PATH)
