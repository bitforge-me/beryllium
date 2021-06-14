import os
import binascii
import re
import io
import hashlib

import pywaves
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From
from flask import url_for
import qrcode
import qrcode.image.svg

from app_core import app

def send_email(logger, subject, msg, recipient=None):
    if not recipient:
        recipient = app.config["ADMIN_EMAIL"]
    from_email = From(app.config["FROM_EMAIL"], app.config["FROM_NAME"])
    template_path = "templates/email_template.html"
    with open(os.path.join(os.path.dirname(__file__), template_path), 'r') as input_file:
        html = input_file.read()
    logo_src = app.config["LOGO_EMAIL_SRC"]
    html = html.replace("<LOGOSRC/>", logo_src).replace("<EMAILCONTENT/>", msg)
    message = Mail(from_email=from_email, to_emails=recipient, subject=subject, html_content=html)
    try:
        sg = SendGridAPIClient(app.config["MAIL_SENDGRID_API_KEY"])
        sg.send(message)
    except Exception as ex: # pylint: disable=broad-except
        logger.error(f"email '{subject}': {ex}")

def email_exception(logger, msg):
    send_email(logger, "premio stage exception", msg)

def email_payment_claim(logger, asset_name, payment, hours_expiry):
    url = url_for("claim_payment", token=payment.token, _external=True)
    msg = f"You have a {asset_name} payment waiting!<br/><br/>Claim your payment <a href='{url}'>here</a><br/><br/>Claim within {hours_expiry} hours"
    send_email(logger, f"Claim your {asset_name} payment", msg, payment.email)

def email_payment_sent(logger, asset_name, payment):
    msg = f"You have been sent a {asset_name} payment!<br/><br/>Check your app for details"
    send_email(logger, f"Received {asset_name} payment", msg, payment.email)

def email_user_create_request(logger, req, minutes_expiry):
    url = url_for("paydb.user_registration_confirm", token=req.token, _external=True)
    msg = f"You have a pending user registration waiting!<br/><br/>Confirm your registration <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, "Confirm your registration", msg, req.email)

def email_user_update_email_request(logger, req, minutes_expiry):
    url = url_for("paydb.user_update_email_confirm", token=req.token, _external=True)
    msg = f"You have a pending update email request waiting!<br/><br/>Confirm your new email <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, "Confirm your update email request", msg, req.email)

def email_api_key_request(logger, req, minutes_expiry):
    url = url_for("paydb.api_key_confirm", token=req.token, secret=req.secret, _external=True)
    msg = f"You have a pending api key request waiting!<br/><br/>Confirm your registration <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, "Confirm your api key request", msg, req.user.email)

def sms_payment_claim(logger, asset_name, payment, hours_expiry):
    # SMS messages are sent by burst SMS
    #  - the authorization is by the sender email
    #  - the country code is configured by the account
    url = url_for("claim_payment", token=payment.token, _external=True)
    msg = f"You have a {asset_name} payment waiting! Claim your payment (within {hours_expiry} hours) {url}"
    email = str(payment.mobile) + "@transmitsms.com"
    send_email(logger, "{asset_name} Payment", msg, email)

def email_stash_save_request(logger, email, req, minutes_expiry):
    url = url_for("stash_bp.stash_save_confirm", token=req.token, secret=req.secret, _external=True)
    msg = f"You have a pending stash save request waiting!<br/><br/>Confirm your stash <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, "Confirm your stash request", msg, email)

def email_stash_save_exists(logger, email, req):
    msg = "We have received a request to store a stash for you but you already have a stash<br/><br/>"
    send_email(logger, "Your stash already exists", msg, email)

def email_stash_load_request(logger, email, req, minutes_expiry):
    url = url_for("stash_bp.stash_load_confirm", token=req.token, secret=req.secret, _external=True)
    msg = f"You have a pending stash load request waiting!<br/><br/>Confirm the request came from you <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, "Confirm your stash request", msg, email)

def generate_key(num=20):
    return binascii.hexlify(os.urandom(num)).decode()

def is_email(val):
    return re.match("[^@]+@[^@]+\.[^@]+", val) # pylint: disable=anomalous-backslash-in-string

def is_mobile(val):
    return val.isnumeric()

def is_address(val):
    try:
        return pywaves.validateAddress(val)
    except: # pylint: disable=bare-except
        return False

def qrcode_svg_create(data, box_size=10):
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(data, image_factory=factory, box_size=box_size)
    output = io.BytesIO()
    img.save(output)
    svg = output.getvalue().decode('utf-8')
    return svg

def str2bytes(string):
    # warning this method is flawed with some input
    return string.encode("latin-1")

def sha256(string):
    data = str2bytes(string)
    raw_hash = hashlib.sha256(data).digest()
    return binascii.hexlify(raw_hash).decode()
