# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os
import hashlib

from ..constants import (
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH
)


def encrypt(salt, password):
    if not isinstance(password, bytes):
        password = password.encode()

    return hashlib.sha512(password + salt).digest()


class Encrypt:

    def generate_cipher(self):
        raise NotImplementedError()

    def reset(self):
        self.destroy()
        self.generate_cipher()

    def destroy(self):
        os.unlink(PRIVATE_KEY_PATH)
        os.unlink(PUBLIC_KEY_PATH)
