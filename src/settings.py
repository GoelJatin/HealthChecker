# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os

from flask import Flask


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = (
    'sqlite:///'
    f'{os.path.join(os.getcwd(), "database.db")}'
).replace("\\", "/")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'SpiceworksHealthCheckerApp'
