import json
import hmac
import base64

import requests
import base58
import pywaves
import pyblake2

import config

cfg = config.read_cfg()

def txid_from_txdata(payload):
    txid = pyblake2.blake2b(payload, digest_size=32).digest()
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

def create_signed_payment_notification(txid, timestamp, recipient, from_, amount, invoice_id):
    d = {"txid": txid, "timestamp": timestamp, "recipient": recipient,\
            "from": from_, "amount": amount, "invoice_id": invoice_id}
    msg = json.dumps(d)
    sig = hmac.HMAC(cfg.webhook_key.encode(), msg.encode(), "sha256").digest()
    sig = base64.b64encode(sig)
    return msg, sig

def call_webhook(logger, msg, sig):
    try:
        headers = {"Content-Type": "application/json", "Signature": sig}
        response = requests.post(cfg.webhook_url, headers=headers, data=msg)
        if response.ok:
            logger.info(f"called {cfg.webhook} ok")
        else:
            logger.error(f"{cfg.webhook}: {response.status_code} - {response.text}")
    except Exception as ex:
        logger.error(f"call_webhook: {ex}")
