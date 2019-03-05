# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""


import random
import string
import uuid

import pytest

from src.encryption_ops.decryption import Decryption
from src.encryption_ops.encrypt import encrypt
from src.encryption_ops.encryption import Encryption


SALT = uuid.uuid4().bytes
PASSWORD = 'Test!123'
ENCRYPTED_PASSWORD = encrypt(SALT, PASSWORD)
MESSAGE = ''.join([random.choice(string.ascii_letters) for i in range(random.randrange(10, 50))])
ENCRYPTED_MESSAGES = []
DECRYPTED_MESSAGES = []


class TestEncrypt:

    @staticmethod
    def test_encrypt_with_incorrect_salt():
        salt = uuid.uuid4().bytes
        assert ENCRYPTED_PASSWORD != encrypt(salt, PASSWORD)

    @staticmethod
    def test_encrypt_with_incorrect_password():
        password = ''.join([random.choice(string.ascii_letters) for i in range(random.randrange(10, 15))])
        assert ENCRYPTED_PASSWORD != encrypt(SALT, password)

    @staticmethod
    def test_encryption():
        encrypted_messages = []
        for _ in range(random.randrange(5, 10)):
            encryption = Encryption()
            ENCRYPTED_MESSAGES.append(encryption.encrypt(MESSAGE))

        # check each message is encrypted differently
        assert len(set(encrypted_messages)) == len(encrypted_messages)

    @staticmethod
    def test_decryption():
        for i in ENCRYPTED_MESSAGES:
            decryption = Decryption(i['enc_session_key'], i['nonce'])
            assert decryption.decrypt((i['ciphertext'], i['tag'])).decode() == MESSAGE

    @staticmethod
    def test_decryption_failure_invalid_session_key():
        with pytest.raises(Exception):
            message = ENCRYPTED_MESSAGES[random.randrange(len(ENCRYPTED_MESSAGES))]
            decryption = Decryption("", message['nonce'])
            decryption.decrypt((message['ciphertext'], message['tag']))

    @staticmethod
    def test_decryption_failure_invalid_nonce():
        with pytest.raises(Exception):
            message = ENCRYPTED_MESSAGES[random.randrange(len(ENCRYPTED_MESSAGES))]
            decryption = Decryption(message['enc_session_key'], "")
            decryption.decrypt((message['ciphertext'], message['tag']))

    @staticmethod
    def test_decryption_failure_invalid_ciphertext():
        with pytest.raises(Exception):
            message = ENCRYPTED_MESSAGES[random.randrange(len(ENCRYPTED_MESSAGES))]
            decryption = Decryption(message['enc_session_key'], message['nonce'])
            decryption.decrypt(("", message['tag']))

    @staticmethod
    def test_decryption_failure_invalid_tag():
        with pytest.raises(Exception):
            message = ENCRYPTED_MESSAGES[random.randrange(len(ENCRYPTED_MESSAGES))]
            decryption = Decryption(message['enc_session_key'], message['nonce'])
            decryption.decrypt((message['ciphertext'], ""))
