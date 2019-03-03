# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import uuid

from flask_sqlalchemy import SQLAlchemy

from settings import APP
from encryption_ops.encrypt import encrypt
from exception import NoSuchUserException, UserAlreadyExistsException


DB = SQLAlchemy(APP)


class User(DB.Model):
    """Table for storing User related information."""

    __tablename__ = 'Users'

    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(32), nullable=False, unique=True)
    password = DB.Column(DB.String(100), nullable=False)
    salt = DB.Column(DB.String(100), nullable=False)

    def __repr__(self):
        return f'User: {self.username}'

    def get_all_users():
        """Returns the list of all the users added to the Table."""
        return User.query.all()

    def add_user(_username, _password):
        """Add a new user to the Table, if it does not exists.

            Args:
                _username   (str):  username of the new user

                _password   (str):  password of the new user

            Returns:
                None:   if the user is added successfully

            Raises:
                UserAlreadyExistsException:     if a user already exists with the given username

        """
        try:
            User.get_user(_username)
            raise UserAlreadyExistsException('Please give a unique username')
        except NoSuchUserException:
            salt = uuid.uuid4().bytes

            if not isinstance(_password, bytes):
                _password = _password.encode()

            _password = encrypt(salt, _password)

            new_user = User(username=_username, password=_password, salt=salt)
            DB.session.add(new_user)
            DB.session.commit()

    def get_user(_username):
        """Returns a SQLAlchemy object of the row (user) that matches the given username."""
        user = User.query.filter_by(username=_username).first()

        if user:
            return user

        raise NoSuchUserException('No username exists with the given name')

    def delete_user(_username, _password):
        """Deletes the user with the given username, if password also matches."""
        user = User.get_user(_username)

        if user and encrypt(user.salt, _password) == user.password:
            DB.session.delete(user)
            DB.session.commit()
            return True

        return False

    def authenticate(_username, _password):
        """Checks if a user with the given username and password exists in the table or not."""
        user = User.query.filter_by(username=_username).first()

        if user and encrypt(user.salt, _password) == user.password:
            return True

        return False
