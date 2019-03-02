# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

from base64 import b64encode, b64decode, binascii

from flask_sqlalchemy import SQLAlchemy

from ..settings import APP
from ..encryption.encryption import Encryption
from ..encryption.decryption import Decryption
from ..exception import (
    NoSuchResourceException,
    ResourceAlreadyExistsException,
    EncryptionFailedException,
    DecryptionFailedException,
    CorruptedDataException
)


DB = SQLAlchemy(APP)


class Resource(DB.Model):
    """Table for storing Resource related information."""

    __tablename__ = 'Resource'

    id = DB.Column(DB.Integer, primary_key=True)
    hostname = DB.Column(DB.String(50), nullable=False, unique=True)
    username = DB.Column(DB.String(32), nullable=False)
    password = DB.Column(DB.String(100), nullable=False)
    interval = DB.Column(DB.Integer, nullable=False)

    def __repr__(self):
        return (
            f'Resource: {self.hostname}, '
            f'for User: {self.username}, '
            f'with Interval: {self.interval}'
        )

    @staticmethod
    def _encrypt_password(_password):
        """Encrypts and returns the resource password."""
        encryption = Encryption()

        try:
            data = encryption.encrypt(_password)
        except ValueError as error:
            raise EncryptionFailedException(
                f'Failed to encrypt the message due to the error: [{error}]'
            )

        for key in data:
            data[key] = b64encode(data[key])

        return b64encode(str(data).encode()).decode()

    @staticmethod
    def _decrypt_password(_password):
        """Decrypts and returns the resource password."""
        _password = b64decode(_password)
        data = eval(_password)

        try:
            for key in data:
                data[key] = b64decode(data[key])
        except binascii.Error:
            raise CorruptedDataException('Data is corrupted')

        try:
            decryption = Decryption(data['enc_session_key'], data['nonce'])
            _password = decryption.decrypt((data['ciphertext'], data['tag']))
        except ValueError as error:
            raise DecryptionFailedException(
                f'Failed to decrypt the message due to the error: [{error}]'
            )

        return _password.decode()

    def get_all_resources():
        """Returns the list of all the resources added to the Table."""
        return Resource.query.all()

    def add_resource(_hostname, _username, _password, _interval=60):
        """Add a new resource to the Table, if it does not exists.

            Args:
                _hostname   (str):  hostname / ip address of the resource

                _username   (str):  username of the resource

                _password   (str):  password of the resource

                _interval   (int):  interval value to be used b/w consecutive pings (in seconds)

                    default:    60

            Returns:
                None:   if the resource is added successfully

            Raises:
                ResourceAlreadyExistsException:     if resource already exists with given hostname

                EncryptionFailedException:          if encryption failed for the given password

        """
        try:
            Resource.get_resource(_hostname)
            raise ResourceAlreadyExistsException('Please give a unique hostname')
        except NoSuchResourceException:
            _password = Resource._encrypt_password(_password)

            new_resource = Resource(
                hostname=_hostname,
                username=_username,
                password=_password,
                interval=_interval
            )
            DB.session.add(new_resource)
            DB.session.commit()

    def get_resource(_hostname):
        """Returns a SQLAlchemy object of the row (resource) that matches the given hostname."""
        resource = Resource.query.filter_by(hostname=_hostname).first()

        if resource:
            return resource

        raise NoSuchResourceException('No resource exists with the given hostname')

    def delete_resource(_hostname, _username, _password):
        """Deletes the resource with the given hostname, if username and password also matches."""
        resource = Resource.get_resource(_hostname)
        _password = Resource._encrypt_password(_password)

        if resource and _username == resource.username and _password == resource.password:
            DB.session.delete(resource)
            DB.session.commit()
            return True

        return False
