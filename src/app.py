# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os
import json
import datetime

from functools import wraps
from base64 import b64encode, b64decode, binascii

import jwt

from flask import jsonify, request, Response

from settings import APP as app
from database.user_model import DB as DB_User, User
from database.resource_model import DB as DB_Resource, Resource
from encryption_ops.encryption import Encryption
from encryption_ops.decryption import Decryption
from exception import (
    NoSuchUserException,
    UserAlreadyExistsException,
    NoSuchResourceException,
    ResourceAlreadyExistsException
)
from constants import PEM_DIR

from health_aggregator import HealthAggregator


HEALTH_AGGREGATOR = None


def validate_token(func):
    """Decorator for validating the JWT token required for API requests."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        """Tries to decode the JWT token using the SECRET KEY.

            Executes the original function if token is valid.

            Otherwise returns HTTP 401 to the Client.

        """
        token = request.headers.get('token')

        try:
            jwt.decode(token, app.config['SECRET_KEY'])
            return func(*args, **kwargs)
        except jwt.DecodeError:
            message = 'Token is missing / invalid'
        except jwt.exceptions.ExpiredSignatureError:
            message = 'Token has expired'


        return Response(
            json.dumps({'error': message}),
            401,
            mimetype='application/json'
        )

    return wrapper


@app.route('/Encrypt', methods=['POST'])
@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypts the **message** parameter received in the request payload,
        and returns the encrypted text, and other details required for its
        decryption.

        Usage
        -----

        POST    -   /Encrypt

        **Request**

            {
                "message": {{ Message to be encrypted }}
            }

        **Response**

            200

                {
                    "enc_session_key": "",

                    "nonce": "",

                    "ciphertext": "",

                    "tag": ""
                }

            400

                - failed to encrypt

                    {
                        "error": f"Failed to encrypt the message due to the error: [{error}]"
                    }

                - **message** parameter is missing

                    {
                        "error": "Message missing in the request body"
                    }

    """
    request_data = request.get_json()

    if 'message' in request_data:
        encryption = Encryption()
        try:
            data = encryption.encrypt(request_data['message'])
        except ValueError as error:
            return Response(
                json.dumps(
                    {
                        'error': f'Failed to encrypt the message due to the error: [{error}]'
                    }
                ),
                400,
                mimetype='application/json'
            )

        for key in data:
            data[key] = b64encode(data[key]).decode()

        return jsonify(data), 200

    return Response(
        json.dumps({'error': 'Message missing in the request body'}),
        400,
        mimetype='application/json'
    )


@app.route('/Decrypt', methods=['POST'])
@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypts the **ciphertext** parameter received in the request payload
        using the other parameters, **enc_session_key**, **nonce**, **tag**,
        and returns the decrypted text as the response.

        Usage
        -----

        POST    -   /Decrypt

        **Request**

            {
                "enc_session_key": "",

                "nonce": "",

                "ciphertext": "",

                "tag": ""
            }

        **Response**

            200

                {
                    "message": {{ Decrypted Message }}
                }

            400

                - encoded data is corrupted

                    {
                        "error": "Malformed payload"
                    }

                - failed to decrypt

                    {
                        "error": f"Failed to decrypt the message due to the error: [{error}]"
                    }

                - required parameters missing

                    {
                        "error": "Tag / Ciphertext / Nonce / Encrypted Session Key missing in the request body"
                    }

    """
    request_data = request.get_json()

    if ('ciphertext' in request_data and
            'tag' in request_data and
            'enc_session_key' in request_data and
            'nonce' in request_data):

        try:
            for key in request_data.keys():
                request_data[key] = b64decode(request_data[key])
        except binascii.Error:
            return Response(
                json.dumps(
                    {
                        'error': 'Malformed payload'
                    }
                ),
                400,
                mimetype='application/json'
            )

        encryption = Decryption(request_data['enc_session_key'], request_data['nonce'])
        try:
            message = encryption.decrypt(
                (request_data['ciphertext'], request_data['tag'])
            ).decode()
        except ValueError as error:
            return Response(
                json.dumps(
                    {
                        'error': f'Failed to decrypt the message due to the error: [{error}]'
                    }
                ),
                400,
                mimetype='application/json'
            )

        return jsonify({'message': message}), 200

    return Response(
        json.dumps(
            {
                'error': (
                    'Tag / Ciphertext / Nonce / Encrypted Session Key'
                    ' missing in the request body'
                )
            }
        ),
        400,
        mimetype='application/json'
    )


@app.route('/Login', methods=['POST'])
@app.route('/login', methods=['POST'])
def login():
    """Validates the given username and password, and returns a JWT token if
        user is authenticated, else returns HTTP 400.

        Usage
        -----

        POST    -   /Login

        **Request**

            {
                "username": {{ username }},

                "password": {{ password }}
            }

        **Response**

            200

                {
                    "token": {{ token }}
                }

            400

                - username / password does not match

                    {
                        "error": "Invalid username / password"
                    }

    """
    request_data = request.get_json()

    if User.authenticate(request_data['username'], request_data['password']):
        expiration = datetime.datetime.now() + datetime.timedelta(minutes=20)
        token = jwt.encode(
            {'exp': expiration},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        ).decode()
        return jsonify({'token': token}), 200

    return Response(
        json.dumps({'error': 'Invalid username / password'}),
        400,
        mimetype='application/json'
    )


@app.route('/Users')
@app.route('/users')
def get_users():
    """Returns the list of all the Users stored in the database."""
    return Response(f"{User.get_all_users()}", 200, mimetype='text/plain')


@app.route('/User', methods=['POST'])
@app.route('/user', methods=['POST'])
@validate_token
def add_user():
    """Adds a new User to the application.

        Usage
        -----

        POST    -   /User

        **Request**

            {
                "username": {{ username }},

                "password": {{ password }}
            }

        **Response**

            201

                ""

            400

                - username is not available

                {
                    "error": "A user already exists with the given username"
                }

                - invalid request

                {
                    "error": "Username / Password missing in the request body"
                }

    """
    request_data = request.get_json()

    if 'username' in request_data and 'password' in request_data:
        try:
            User.add_user(request_data['username'], request_data['password'])
            response = Response('', 201)
            response.headers['Location'] = f'/User/{request_data["username"]}'
            return response
        except UserAlreadyExistsException:
            return Response(
                json.dumps({'error': 'A user already exists with the given username'}),
                400,
                mimetype='application/json'
            )

    return Response(
        json.dumps({'error': 'Username / Password missing in the request body'}),
        400,
        mimetype='application/json'
    )


@app.route('/User/<username>')
@app.route('/user/<username>')
@validate_token
def get_user(username):
    """Returns the information for the given username."""
    try:
        user = User.get_user(username)

        return jsonify(
            {
                'username': user.username
            }
        ), 200
    except NoSuchUserException:
        return Response(
            json.dumps({'error': 'Incorrect Username'}),
            400,
            mimetype='application/json'
        )


@app.route('/User/<username>', methods=['DELETE'])
@app.route('/user/<username>', methods=['DELETE'])
@validate_token
def delete_user(username):
    """Deletes the user with the given Username.

        Usage
        -----

        DELETE  -   /User/{{ username }}

        **Request**

            {
                "password": {{ password }}
            }

        **Response**

            200

                ""

            400

                - username is not correct

                    {
                        "error": "Incorrect Username"
                    }

                - invalid request

                    {
                        "error": "Password missing in the request body"
                    }

    """
    request_data = request.get_json()

    if 'password' in request_data:
        try:
            if User.delete_user(username, request_data['password']):
                return Response('', 200, mimetype='application/json')
        except NoSuchUserException:
            return Response(
                json.dumps({'error': 'Incorrect Username'}),
                400,
                mimetype='application/json'
            )

    return Response(
        json.dumps({'error': 'Password missing in the request body'}),
        400,
        mimetype='application/json'
    )


@app.route('/Resources')
@app.route('/resources')
def get_resources():
    """Returns the list of all the Resources stored in the database."""
    return Response(f"{Resource.get_all_resources()}", 200, mimetype='text/plain')


@app.route('/Resource', methods=['POST'])
@app.route('/resource', methods=['POST'])
@validate_token
def add_resource():
    """Adds a new Resource to the application.

        Usage
        -----

        POST    -   /Resource

        **Request**

            {
                "hostname": {{ hostname }},

                "username": {{ username }},

                "password": {{ password }}
            }

        **Response**

            201

                ""

            400

                - hostname is not available

                {
                    "error": "A resource already exists with the given hostname"
                }

                - invalid request

                {
                    "error": "Hostname / Username / Password missing in the request body"
                }

    """
    request_data = request.get_json()

    if 'hostname' in request_data and 'username' in request_data and 'password' in request_data:
        try:
            Resource.add_resource(
                request_data['hostname'],
                request_data['username'],
                request_data['password'],
                request_data.get('interval', 60)
            )

            HEALTH_AGGREGATOR.synchronize()

            return Response('', 201)
        except ResourceAlreadyExistsException:
            return Response(
                json.dumps({'error': 'A resource already exists with the given hostname'}),
                400,
                mimetype='application/json'
            )

    return Response(
        json.dumps({'error': 'Hostname / Username / Password missing in the request body'}),
        400,
        mimetype='application/json'
    )


@app.route('/Resource/<hostname>')
@app.route('/resource/<hostname>')
@validate_token
def get_resource(hostname):
    """Returns the information for the given hostname."""
    try:
        resource = Resource.get_resource(hostname)

        return jsonify(
            {
                'hostname': resource.hostname,
                'username': resource.username,
                'interval': resource.interval
            }
        ), 200
    except NoSuchResourceException:
        return Response(
            json.dumps({'error': 'Incorrect hostname'}),
            400,
            mimetype='application/json'
        )


@app.route('/Resource/<hostname>', methods=['PUT'])
@app.route('/resource/<hostname>', methods=['PUT'])
@validate_token
def update_resource_credentials(hostname):
    """Update the credentials of the resource that matches the given hostname."""
    request_data = request.get_json()

    if 'username' in request_data and 'password' in request_data:
        try:
            Resource.update_resource(
                request_data['hostname'],
                request_data['username'],
                request_data['password'],
                request_data.get('interval')
            )

            return Response('', 200)
        except NoSuchResourceException:
            return Response(
                json.dumps({'error': 'Incorrect hostname'}),
                400,
                mimetype='application/json'
            )

    return Response(
        json.dumps({'error': 'Username / Password missing in the request body'}),
        400,
        mimetype='application/json'
    )


@app.route('/Resource/<hostname>', methods=['PATCH'])
@app.route('/resource/<hostname>', methods=['PATCH'])
@validate_token
def update_resource_interval(hostname):
    """Update the polling interval period of the resource that matches the given hostname."""
    request_data = request.get_json()

    if 'interval' in request_data:
        try:
            Resource.update_resource_interval(
                request_data['hostname'],
                request_data['interval']
            )

            return Response('', 200)
        except NoSuchResourceException:
            return Response(
                json.dumps({'error': 'Incorrect hostname'}),
                400,
                mimetype='application/json'
            )

    return Response(
        json.dumps({'error': 'Interval value missing in the request body'}),
        400,
        mimetype='application/json'
    )


@app.route('/Resource/<hostname>', methods=['DELETE'])
@app.route('/resource/<hostname>', methods=['DELETE'])
@validate_token
def delete_resource(hostname):
    """Deletes the resource with the given hostname.

        Usage
        -----

        DELETE  -   /Resource/{{ hostname }}

        **Request**

            {
                "username": {{ username }},

                "password": {{ password }}
            }

        **Response**

            200

                ""

            400

                - hostname is not correct

                    {
                        "error": "Incorrect hostname"
                    }

                - invalid request

                    {
                        "error": "Username / Password missing in the request body"
                    }

    """
    request_data = request.get_json()

    if 'username' in request_data and 'password' in request_data:
        try:
            if Resource.delete_resource(
                    hostname, request_data['username'], request_data['password']
            ):
                HEALTH_AGGREGATOR.synchronize()
                return Response('', 200, mimetype='application/json')
        except NoSuchResourceException:
            return Response(
                json.dumps({'error': 'Incorrect hostname'}),
                400,
                mimetype='application/json'
            )

    return Response(
        json.dumps({'error': 'Username / Password missing in the request body'}),
        400,
        mimetype='application/json'
    )


@app.route('/Routes')
@app.route('/routes')
def get_routes():
    output = [f'{"S. No.":6}\t{"Endpoint":50}\t{"Method":8}\n']

    for index, rule in enumerate(app.url_map.iter_rules()):
        for i, method in enumerate(rule.methods):
            output.append(f'{index + 1 if i == 0 else "":<6}\t{rule.rule:50}\t{method:10}')

        try:
            output.append(f'\n{eval(rule.endpoint).__doc__}\n')
        except NameError:
            output.append('\n')

    return Response('\n'.join(output), 200, mimetype='text/plain')


@app.route('/IsHealthy')
@app.route('/ishealthy')
def is_healthy():
    status = HEALTH_AGGREGATOR.is_healthy()

    if status is True:
        status_code = 200
    else:
        status_code = 503

    return Response('', status_code, mimetype='text/plain')


def main():
    global HEALTH_AGGREGATOR

    os.makedirs(PEM_DIR, exist_ok=True)

    if not os.path.exists(f'{os.path.join(os.getcwd(), "database.db")}'):
        DB_User.create_all()
        DB_Resource.create_all()

        User.add_user('SpiceWorks', 'HealthChecker')

    HEALTH_AGGREGATOR = HealthAggregator()
    app.run(port=5000)
    HEALTH_AGGREGATOR.cleanup()


if __name__ == '__main__':
    main()
