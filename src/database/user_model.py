# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import uuid

from flask_sqlalchemy import SQLAlchemy

from settings import app
from encryption.encryption import encrypt


DB = SQLAlchemy(app)


class User(DB.Model):
    __tablename__ = 'Users'

    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(32), nullable=False, unique=True)
    password = DB.Column(DB.String(100), nullable=False)
    salt = DB.Column(DB.String(100), nullable=False)

    def __repr__(self):
        return f'User: {self.username}'

    def get_all_users():
        return User.query.all()

    def add_user(_username, _password):
        salt = uuid.uuid4().bytes

        if not isinstance(_password, bytes):
            _password = _password.encode()

        _password = encrypt(salt, _password)

        new_user = User(username=_username, password=_password, salt=salt)
        DB.session.add(new_user)
        DB.session.commit()

    def authenticate(_username, _password):
        user = User.query.filter_by(username=_username).first()

        if user and encrypt(user.salt, _password) == user.password:
            return True

        return False
