#!/usr/bin/python3

import os
import binascii
import sys

def generate_key(num=20):
    return binascii.hexlify(os.urandom(num)).decode()

dir_path = os.path.dirname(os.path.realpath(__file__))
fn = os.path.join(dir_path, "flask_config_secret.py")

sendgrid_api_key = sys.argv[1]

if not os.path.exists(fn):
    template = """SECRET_KEY = '%s'
SECURITY_PASSWORD_SALT = '%s'
MAIL_SENDGRID_API_KEY = '%s'"""
    body = template % (generate_key(), generate_key(), sendgrid_api_key)
    with open(fn, "w") as f:
        f.write(body)
