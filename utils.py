import os
import json
import hmac
import base64
import smtplib
import binascii
import re

import requests
import base58
import pywaves
import pyblake2
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From
from flask import url_for

from app_core import app

def txid_from_txdata(serialized_txdata):
    txid = pyblake2.blake2b(serialized_txdata, digest_size=32).digest()
    return base58.b58encode(txid)

def create_sig_from_msg(key, msg):
    sig = hmac.HMAC(key.encode(), msg.encode(), "sha256").digest()
    sig = base64.b64encode(sig)
    return sig

def send_email(logger, subject, msg, to=None):
    if not to:
        to = app.config["ADMIN_EMAIL"]
    from_email = From(app.config["FROM_EMAIL"], app.config["FROM_NAME"])
    template_path = "templates/email_template.html"
    with open(os.path.join(os.path.dirname(__file__), template_path), 'r') as input_file:
        html = input_file.read()
    logo_src = app.config["SERVER_NAME"] + "/static/assets/img/logo.png"
    html = html.replace("<LOGOSRC/>", logo_src).replace("<EMAILCONTENT/>", msg)
    message = Mail(from_email=from_email, to_emails=to, subject=subject, html_content=html)
    try:
        sg = SendGridAPIClient(app.config["MAIL_SENDGRID_API_KEY"])
        response = sg.send(message)
    except Exception as ex:
        logger.error(f"email '{subject}': {ex}")

def email_exception(logger, msg):
    send_email(logger, "premio stage exception", msg)

def email_payment_claim(logger, asset_name, payment, hours_expiry):
    url = url_for("claim_payment", token=payment.token, _external=True)
    msg = f"You have a {asset_name} payment waiting!<br/><br/>Claim your payment <a href='{url}'>here</a><br/><br/>Claim within {hours_expiry} hours"
    send_email(logger, f"Claim your {asset_name} payment", msg, payment.email)

def email_user_create_request(logger, req, minutes_expiry):
    url = url_for("paydb.user_registration_confirm", token=req.token, _external=True)
    msg = f"You have a pending user registration waiting!<br/><br/>Confirm your registration <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, f"Confirm your registration", msg, req.email)

def sms_payment_claim(logger, asset_name, payment, hours_expiry):
    # SMS messages are sent by burst SMS
    #  - the authorization is by the sender email
    #  - the country code is configured by the account
    url = url_for("claim_payment", token=payment.token, _external=True)
    msg = f"You have a {asset_name} payment waiting! Claim your payment (within {hours_expiry} hours) {url}"
    email = str(payment.mobile) + "@transmitsms.com"
    send_email(logger, "{asset_name} Payment", msg, email)

def generate_key(num=20):
    return binascii.hexlify(os.urandom(num)).decode()

def is_email(s):
    return re.match("[^@]+@[^@]+\.[^@]+", s)

def is_mobile(s):
    return s.isnumeric()

def is_address(s):
    try:
        return pywaves.validateAddress(s)
    except:
        return False

if __name__ == "__main__":
    import sys
    key = sys.argv[1]
    msg = sys.argv[2]
    sig = create_sig_from_msg(key, msg)
    print(sig)
