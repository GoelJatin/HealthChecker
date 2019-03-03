# -*- coding: utf-8 -*-

"""
@author: Jatin Goel

File for storing all the scripts paths.

"""

import os

# Scripts Directories
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Scripts')
WINDOWS_SCRIPTS_DIR = os.path.join(SCRIPTS_DIR, 'Windows')
UNIX_SCRIPTS_DIR = os.path.join(SCRIPTS_DIR, 'UNIX')

# Windows Scripts
CREDENTIALS = os.path.join(WINDOWS_SCRIPTS_DIR, 'Creds.ps1')
EXECUTE_COMMAND = os.path.join(WINDOWS_SCRIPTS_DIR, 'ExecuteCommand.ps1')
