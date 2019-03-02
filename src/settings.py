# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os

from flask import Flask


APP = Flask(__name__)

APP.config['SQLALCHEMY_DATABASE_URI'] = (
    'sqlite:///'
    f'{os.path.join(os.getcwd(), "database.db")}'
).replace("\\", "/")

APP.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

APP.config['SECRET_KEY'] = 'SpiceworksHealthCheckerApp'
