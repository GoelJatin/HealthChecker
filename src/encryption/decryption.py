# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import (
    AES,
    PKCS1_OAEP
)

from ..constants import PRIVATE_KEY_PATH

from .encrypt import Encrypt


class Decryption(Encrypt):

    def __init__(self, enc_session_key, nonce):
        self._decryption_cipher = None
        self.enc_session_key = enc_session_key
        self.nonce = nonce
        self.generate_cipher()

    @property
    def decryption_cipher(self):
        if self._decryption_cipher:
            return self._decryption_cipher

        raise Exception('Decryption cipher is not initialized')

    def generate_cipher(self):
        self._decryption_cipher = AES.new(
            PKCS1_OAEP.new(RSA.import_key(open(PRIVATE_KEY_PATH).read())).decrypt(self.enc_session_key),
            AES.MODE_EAX,
            self.nonce
        )

    def decrypt(self, message):
        try:
            if not isinstance(message, tuple) and len(message) != 2:
                raise Exception('Message should be a tuple with the length 2, as returned by encrypt')

            return self.decryption_cipher.decrypt_and_verify(*message)
        except ValueError:
            raise Exception('Invalid Ciphertext. Please check the text again!')

    def destroy(self):
        super().destroy()
        self._decryption_cipher = None
