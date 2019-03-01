# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import os


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PEM_DIR = os.path.join(ROOT_DIR, 'keys')

PRIVATE_KEY_PATH = os.path.join(PEM_DIR, 'private.pem')
PUBLIC_KEY_PATH = os.path.join(PEM_DIR, 'public.pem')
