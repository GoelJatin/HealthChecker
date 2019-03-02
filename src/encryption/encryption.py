# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os
import hashlib

from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import (
    AES,
    PKCS1_OAEP
)

from ..constants import (
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH
)

from .encrypt import Encrypt


class Encryption(Encrypt):

    def __init__(self):
        self.session_key = None
        self._encryption_cipher = None
        self.generate_cipher()

    @property
    def encryption_cipher(self):
        if self._encryption_cipher:
            return self._encryption_cipher
        
        raise Exception('Encryption cipher is not initialized')

    def generate_cipher(self):
        if not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
            key = RSA.generate(2048)

            with open(PRIVATE_KEY_PATH, "wb") as file_out:
                file_out.write(key.export_key())

            with open(PUBLIC_KEY_PATH, "wb") as file_out:
                file_out.write(key.publickey().export_key())

        self.session_key = get_random_bytes(16)

        self._encryption_cipher = AES.new(self.session_key, AES.MODE_EAX)

    def encrypt(self, message):
        try:
            if not isinstance(message, bytes):
                message = message.encode()

            enc_session_key = PKCS1_OAEP.new(RSA.import_key(open(PUBLIC_KEY_PATH).read())).encrypt(self.session_key)
            ciphertext, tag = self.encryption_cipher.encrypt_and_digest(message)
            nonce = self.encryption_cipher.nonce

            return {
                'enc_session_key': enc_session_key,
                'nonce': nonce,
                'ciphertext': ciphertext,
                'tag': tag
            }
        except ValueError:
            raise Exception('Invalid text given. Please check the text again!')

    def destroy(self):
        super().destroy()
        self._encryption_cipher = None
