# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import json
import uuid

from base64 import b64encode

from flask_sqlalchemy import SQLAlchemy

from settings import app
from encryption.encryption import encrypt, Encryption
from exception import NoSuchResourceException, ResourceAlreadyExistsException, EncryptionFailedException


DB = SQLAlchemy(app)


class Resource(DB.Model):
    __tablename__ = 'Resource'

    id = DB.Column(DB.Integer, primary_key=True)
    hostname = DB.Column(DB.String(50), nullable=False, unique=True)
    username = DB.Column(DB.String(32), nullable=False)
    password = DB.Column(DB.String(100), nullable=False)

    def __repr__(self):
        return f'Resource: {self.hostname}, for User: {self.username}'

    def get_all_resources():
        return Resource.query.all()

    def add_resource(_hostname, _username, _password):
        try:
            Resource.get_resource(_hostname)
            raise ResourceAlreadyExistsException('Please give a unique hostname')
        except NoSuchResourceException:
            encryption = Encryption()

            try:
                data = encryption.encrypt(_password)
            except ValueError as error:
                raise EncryptionFailedException(f'Failed to encrypt the message due to the error: [{error}]')

            for key in data.keys():
                data[key] = b64encode(data[key])

            _password = b64encode(str(data).encode()).decode()

            new_resource = Resource(hostname=_hostname, username=_username, password=_password)
            DB.session.add(new_resource)
            DB.session.commit()

    def get_resource(_hostname):
        resource = Resource.query.filter_by(hostname=_hostname).first()

        if resource:
            return resource

        raise NoSuchResourceException('No resource exists with the given hostname')

    def delete_resource(_hostname, _username, _password):
        resource = Resource.get_resource(_hostname)

        if resource and _username == resource.username and _password == resource.password:
            DB.session.delete(resource)
            DB.session.commit()
            return True

        return False
