# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os
import json
import jwt
import datetime

from functools import wraps
from base64 import b64encode, b64decode

from flask import jsonify, request, Response

from settings import app
from database.user_model import DB as DB_User, User
from encryption.encryption import Encryption, Decryption

from constants import PEM_DIR


def validate_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('token')

        try:
            jwt.decode(token, app.config['SECRET_KEY'])
            return func(*args, **kwargs)
        except jwt.DecodeError:
            return Response(
                json.dumps({'error': 'Token is missing / invalid'}),
                401,
                mimetype='application/json'
            )

    return wrapper


@app.route('/Encrypt', methods=['POST'])
def encrypt():
    request_data = request.get_json()

    if 'message' in request_data:
        encryption = Encryption()
        data = encryption.encrypt(request_data['message'])

        print(data)

        for key in data.keys():
            data[key] = b64encode(data[key])

        return jsonify(data), 200

    return Response(json.dumps({'error': 'Message missing in the request body'}), 401, mimetype='application/json')


@app.route('/Decrypt', methods=['POST'])
def decrypt():
    request_data = request.get_json()

    if ('ciphertext' in request_data and
            'tag' in request_data and
            'enc_session_key' in request_data and
            'nonce' in request_data):

        for key in request_data.keys():
            request_data[key] = b64decode(request_data[key])

        print(request_data)

        encryption = Decryption(request_data['enc_session_key'], request_data['nonce'])
        message = encryption.decrypt(
            (request_data['ciphertext'], request_data['tag'])
        )

        return jsonify({'message': message}), 200

    return Response(
        json.dumps({'error': 'Tag / Ciphertext / Nonce / Encrypted Session Keymissing in the request body'}),
        401,
        mimetype='application/json'
    )


@app.route('/login', methods=['POST'])
def login():
    request_data = request.get_json()

    if User.authenticate(request_data['username'], request_data['password']):
        expiration = datetime.datetime.now() + datetime.timedelta(minutes=20)
        token = jwt.encode(
            {'exp': expiration},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        ).decode()
        return jsonify({'token': token}), 200

    return Response('', 401, mimetype='application/json')


@app.route('/users')
def get_books():
    return f"{User.get_all_users()}"
    

if __name__ == '__main__':
    os.makedirs(PEM_DIR, exist_ok=True)

    if not os.path.exists(f'{os.path.join(os.getcwd(), "database.db")}'):
        DB_User.create_all()

    app.run(port=5000)
