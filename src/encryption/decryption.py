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
    """Class for decryption operations using the given encrypted session key and nonce."""

    def __init__(self, enc_session_key, nonce):
        """Creates an object of AES cipher using the RSA Private key and the
            given encrypted session key and nonce.

        """
        self._decryption_cipher = None
        self.enc_session_key = enc_session_key
        self.nonce = nonce
        self._generate_cipher()

    def _generate_cipher(self):
        """Creates an object of AES cipher using the RSA Private key and the
            given encrypted session key and nonce.

        """
        self._decryption_cipher = AES.new(
            PKCS1_OAEP.new(
                RSA.import_key(open(PRIVATE_KEY_PATH).read())
            ).decrypt(self.enc_session_key),
            AES.MODE_EAX,
            self.nonce
        )

    @property
    def decryption_cipher(self):
        """Returns instance of the decryption cipher."""
        if self._decryption_cipher:
            return self._decryption_cipher

        raise Exception('Decryption cipher is not initialized')

    def decrypt(self, message):
        """Decrypts the given message."""
        try:
            if not isinstance(message, tuple) and len(message) != 2:
                raise Exception(
                    'Message should be a tuple with the length 2, as returned by encrypt'
                )

            return self.decryption_cipher.decrypt_and_verify(*message)
        except ValueError:
            raise Exception('Invalid Ciphertext. Please check the text again!')

    def destroy(self):
        super().destroy()
        self._decryption_cipher = None
