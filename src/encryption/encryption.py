# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os

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
    """Class for encryption operations using the AES cipher and RSA Public Key."""

    def __init__(self):
        """Creates an object of AES cipher using a session key."""
        self.session_key = None
        self._encryption_cipher = None
        self._generate_cipher()

    def _generate_cipher(self):
        """Creates an object of AES cipher using a session key."""
        if not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
            key = RSA.generate(2048)

            with open(PRIVATE_KEY_PATH, "wb") as file_out:
                file_out.write(key.export_key())

            with open(PUBLIC_KEY_PATH, "wb") as file_out:
                file_out.write(key.publickey().export_key())

        self.session_key = get_random_bytes(16)

        self._encryption_cipher = AES.new(self.session_key, AES.MODE_EAX)

    @property
    def encryption_cipher(self):
        """Returns instance of the encryption cipher."""
        if self._encryption_cipher:
            return self._encryption_cipher

        raise Exception('Encryption cipher is not initialized')

    def encrypt(self, message):
        """Encrypts the given message using the RSA Public Key,
            and returns the ciphertext,
            and other attributes needed for its decryption.

            Args:
                message     (str / bytes):  text / data to be encrypted

            Returns:
                dict:   dictionary consisting of,

                - **enc_session_key**:  encrypted session key
                - **nonce**:            AES cipher NONCE
                - **ciphertext**:       encrypted data
                - **tag**:              tag consisting information for the data

        """
        try:
            if not isinstance(message, bytes):
                message = message.encode()

            enc_session_key = PKCS1_OAEP.new(
                RSA.import_key(open(PUBLIC_KEY_PATH).read())
            ).encrypt(self.session_key)
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
