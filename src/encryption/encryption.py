# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os
import hashlib

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import (
    AES,
    PKCS1_OAEP
)

from constants import (
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH
)


def encrypt(salt, password):
    if not isinstance(password, bytes):
        password = password.encode()

    return hashlib.sha512(password + salt).digest()


class Encryption:

    def __init__(self):
        self.generate_cipher()

    @property
    def encryption_cipher(self):
        if self._encryption_cipher:
            return self._encryption_cipher
        
        raise Exception('Encryption cipher is not initialized')

    @property
    def decryption_cipher(self):
        if self._decryption_cipher:
            return self._decryption_cipher
        
        raise Exception('Decryption cipher is not initialized')

    def generate_cipher(self):
        if not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
            key = RSA.generate(2048)

            with open(PRIVATE_KEY_PATH, "wb") as file_out:
                file_out.write(key.export_key())

            with open(PUBLIC_KEY_PATH, "wb") as file_out:
                file_out.write(key.publickey().export_key())

        session_key = get_random_bytes(16)
        enc_session_key = PKCS1_OAEP.new(RSA.import_key(open(PUBLIC_KEY_PATH).read())).encrypt(session_key)

        self._encryption_cipher = AES.new(session_key, AES.MODE_EAX)
        self._decryption_cipher = AES.new(
            PKCS1_OAEP.new(RSA.import_key(open(PRIVATE_KEY_PATH).read())).decrypt(enc_session_key),
            AES.MODE_EAX,
            self.encryption_cipher.nonce
        )

    def encrypt(self, message):
        try:
            if not isinstance(message, bytes):
                message = message.encode()

            return self.encryption_cipher.encrypt_and_digest(message)
        except ValueError:
            raise Exception('Invalid text given. Please check the text again!')

    def decrypt(self, message):
        try:
            if not isinstance(message, tuple) and len(message) != 2:
                raise Exception('Message should be a tuple with the length 2, as returned by encrypt')

            return self.decryption_cipher.decrypt_and_verify(*message)
        except ValueError:
            raise Exception('Invalid Ciphertext. Please check the text again!')

    def reset(self):
        self.destroy()
        self.generate_cipher()

    def destroy(self):
        os.unlink(PRIVATE_KEY_PATH)
        os.unlink(PUBLIC_KEY_PATH)
        self._encryption_cipher = self._decryption_cipher = None


if __name__ == "__main__":
    E = Encryption()
