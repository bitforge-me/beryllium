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
from sendgrid.helpers.mail import Mail

import config

cfg = config.read_cfg()

def txid_from_txdata(serialized_txdata):
    txid = pyblake2.blake2b(serialized_txdata, digest_size=32).digest()
    return base58.b58encode(txid)

def extract_invoice_id(logger, attachment):
    try:
        data = json.loads(attachment)
        if "invoice_id" in data:
            return data["invoice_id"]
    except Exception as ex:
        logger.error(f"extract_invoice_id: {ex}")
    return None

def address_from_public_key(public_key, b58encoded=False):
    if b58encoded:
        pubkey = base58.b58decode(public_key)
    else:
        pubkey = public_key
    unhashed_address = chr(1) + str(pywaves.CHAIN_ID) + pywaves.crypto.hashChain(pubkey)[0:20]
    addr_hash = pywaves.crypto.hashChain(pywaves.crypto.str2bytes(unhashed_address))[0:4]
    return base58.b58encode(pywaves.crypto.str2bytes(unhashed_address + addr_hash))

def create_sig_from_msg(key, msg):
    sig = hmac.HMAC(key.encode(), msg.encode(), "sha256").digest()
    sig = base64.b64encode(sig)
    return sig

def create_signed_payment_notification(txid, timestamp, recipient, sender, amount, invoice_id):
    d = {"txid": txid, "timestamp": timestamp, "recipient": recipient,\
            "sender": sender, "amount": amount, "invoice_id": invoice_id}
    msg = json.dumps(d)
    sig = create_sig_from_msg(cfg.webhook_key, msg)
    return msg, sig

def call_webhook(logger, msg, sig):
    try:
        headers = {"Content-Type": "application/json", "Signature": sig}
        logger.debug(f"calling '{cfg.webhook_url}' with headers ({headers}) and body ({msg})") 
        response = requests.post(cfg.webhook_url, headers=headers, data=msg)
        if response.ok:
            logger.info(f"called {cfg.webhook_url} ok")
        else:
            logger.error(f"{cfg.webhook_url}: {response.status_code} - {response.text}")
    except Exception as ex:
        logger.error(f"call_webhook: {ex}")

def send_email(logger, subject, msg):
    message = Mail(from_email=cfg.email_from, to_emails=cfg.email_admin, subject=subject, html_content=msg)
    try:
        import flask_config_secret
        sg = SendGridAPIClient(flask_config_secret.MAIL_SENDGRID_API_KEY)
        response = sg.send(message)
    except Exception as ex:
        logger.error(f"email '{subject}': {ex}")

def email_death(logger, msg):
    send_email(logger, "zapd is dead", msg)

def email_alive(logger, msg):
    send_email(logger, "zapd is alive", msg)

def email_exception(logger, msg):
    send_email(logger, "zapd exception", msg)

def email_buffer(logger, msg, buf):
    msg = f"{msg}\n\n{buf}"
    send_email(logger, "zapd buffer issue", msg)

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
