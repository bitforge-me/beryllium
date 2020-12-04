#!/usr/bin/python3

import sys
import logging
import json
import struct
import time
import datetime
import decimal

import gevent
from gevent.pywsgi import WSGIServer
from flask import Flask, render_template, request, flash, abort
from flask_jsonrpc import JSONRPC
from flask_jsonrpc.exceptions import OtherError
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import base58
import pywaves
import pyblake2

from app_core import app, db
from models import CreatedTransaction, Proposal, Payment
import admin
import utils

jsonrpc = JSONRPC(app, "/api")
logger = logging.getLogger(__name__)

# our address object
pw_address = None

# created transaction states
CTX_CREATED = "created"
CTX_EXPIRED = "expired"
CTX_BROADCAST = "broadcast"

# response error codes
ERR_FAILED_TO_BROADCAST = 0
ERR_NO_TXID = 1
ERR_TX_EXPIRED = 2
ERR_FAILED_TO_GET_ASSET_INFO = 3
ERR_EMPTY_ADDRESS = 4

NODE_BASE_URL = app.config["NODE_BASE_URL"]
SEED = app.config["WALLET_SEED"]
ADDRESS = app.config["WALLET_ADDRESS"]
ASSET_ID = app.config["ASSET_ID"]

#
# helper functions
#

def get(url):
    with requests.Session() as s:
        retries = Retry(
            total=10,
            backoff_factor=0.2,
            status_forcelist=[500, 502, 503, 504])
        s.mount('http://', HTTPAdapter(max_retries=retries))
        s.mount('https://', HTTPAdapter(max_retries=retries))
        response = s.get(url)
        return response

def dashboard_data():
    # get balance of local wallet
    path = f"assets/balance/{ADDRESS}/{ASSET_ID}"
    response = requests.get(NODE_BASE_URL + path)
    zap_balance = response.json()["balance"]
    # get the balance of the main wallet
    path = f"transactions/info/{ASSET_ID}"
    response = requests.get(NODE_BASE_URL + path)
    try:
        issuer = response.json()["sender"]
        path = f"addresses/balance/{issuer}"
        response = requests.get(NODE_BASE_URL + path)
        master_waves_balance = response.json()["balance"]
    except:
        issuer = "n/a"
        master_waves_balance = "n/a"
    # return data
    return {"zap_balance": zap_balance, "zap_address": ADDRESS, \
            "master_waves_balance": master_waves_balance, "master_waves_address": issuer, \
            "asset_id": ASSET_ID, \
            "testnet": app.config["TESTNET"]}

def from_int_to_user_friendly(val, divisor, decimal_places=4):
    if not isinstance(val, int):
        return val
    val = val / divisor
    return round(val, decimal_places)

def _create_transaction(recipient, amount, attachment):
    # get fee
    path = f"assets/details/{ASSET_ID}"
    response = requests.get(NODE_BASE_URL + path)
    if response.ok:
        asset_fee = response.json()["minSponsoredAssetFee"]
    else:
        short_msg = "failed to get asset info"
        logger.error(f"{short_msg}: ({response.status_code}, {response.request.method} {response.url}):\n\t{response.text}")
        err = OtherError(short_msg, ERR_FAILED_TO_GET_ASSET_INFO)
        err.data = response.text
        raise err
    if not recipient:
        short_msg = "recipient is null or an empty string"
        logger.error(short_msg)
        err = OtherError(short_msg, ERR_EMPTY_ADDRESS)
        raise err
    if not utils.is_address(recipient):
        short_msg = "recipient is not a valid address"
        logger.error(short_msg)
        err = OtherError(short_msg, ERR_EMPTY_ADDRESS)
        raise err
    recipient = pywaves.Address(recipient)
    asset = pywaves.Asset(ASSET_ID)
    address_data = pw_address.sendAsset(recipient, asset, amount, attachment, feeAsset=asset, txFee=asset_fee)
    signed_tx = json.loads(address_data["api-data"])
    # calc txid properly
    txid = transfer_asset_txid(signed_tx)
    # store tx in db
    dbtx = CreatedTransaction(txid, CTX_CREATED, signed_tx["amount"], address_data["api-data"])
    return dbtx

def _broadcast_transaction(txid):
    dbtx = CreatedTransaction.from_txid(db.session, txid)
    if not dbtx:
        raise OtherError("transaction not found", ERR_NO_TXID)
    if dbtx.state == CTX_EXPIRED:
        raise OtherError("transaction expired", ERR_TX_EXPIRED)
    signed_tx = dbtx.json_data
    # broadcast
    logger.debug(f"requesting broadcast of tx:\n\t{signed_tx}")
    path = f"assets/broadcast/transfer"
    headers = {"Content-Type": "application/json"}
    response = requests.post(NODE_BASE_URL + path, headers=headers, data=signed_tx)
    if response.ok:
        # update tx in db
        dbtx.state = CTX_BROADCAST
    else:
        short_msg = "failed to broadcast"
        logger.error(f"{short_msg}: ({response.status_code}, {response.request.method} {response.url}):\n\t{response.text}")
        err = OtherError(short_msg, ERR_FAILED_TO_BROADCAST)
        err.data = response.text
        raise err
    return dbtx

#
# Jinja2 filters
#

@app.template_filter()
def int2zap(num):
    num = decimal.Decimal(num)
    return num/100

#
# Flask views
#

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/internal/process_proposals")
def process_proposals():
    # set expired
    expired = 0
    now = datetime.datetime.now()
    proposals = Proposal.in_status(db.session, Proposal.STATE_AUTHORIZED)
    for proposal in proposals:
        if proposal.date_expiry < now:
            proposal.status = Proposal.STATE_EXPIRED
            expired += 1
            db.session.add(proposal)
    db.session.commit()
    # process authorized 
    emails = 0
    sms_messages = 0
    proposals = Proposal.in_status(db.session, Proposal.STATE_AUTHORIZED)
    for proposal in proposals:
        for payment in proposal.payments:
            if payment.status == payment.STATE_CREATED:
                if payment.email:
                    utils.email_payment_claim(logger, payment, proposal.HOURS_EXPIRY)
                    payment.status = payment.STATE_SENT_CLAIM_LINK
                    db.session.add(payment)
                    logger.info(f"Sent payment claim url to {payment.email}")
                    emails += 1
                elif payment.mobile:
                    utils.sms_payment_claim(logger, payment, proposal.HOURS_EXPIRY)
                    payment.status = payment.STATE_SENT_CLAIM_LINK
                    db.session.add(payment)
                    logger.info(f"Sent payment claim url to {payment.mobile}")
                    sms_messages += 1
                elif payment.wallet_address:
                    ##TODO: set status and commit before sending so we cannot send twice
                    raise Exception("not yet implemented")
    db.session.commit()
    logger.info(f"payment statuses commited")
    return f"done (expired {expired}, emails {emails}, SMS messages {sms_messages})"

def process_claim(payment, dbtx):
    if payment.proposal.status != payment.proposal.STATE_AUTHORIZED:
        return dbtx, "payment not authorized"
    if payment.status != payment.STATE_SENT_CLAIM_LINK:
        return dbtx, "payment not authorized"
    # create/get transaction
    if not dbtx:
        try:
            recipient = request.form["recipient"]
            dbtx = _create_transaction(recipient, payment.amount, "")
            payment.txid = dbtx.txid
            db.session.add(dbtx)
            db.session.add(payment)
            db.session.commit()
        except OtherError as ex:
            return dbtx, ex.message
        except ValueError as ex:
            return dbtx, ex
    # broadcast transaction
    try:
        dbtx = _broadcast_transaction(dbtx.txid)
        payment.status = payment.STATE_SENT_FUNDS
        db.session.add(dbtx)
        db.session.commit()
    except OtherError as ex:
        return dbtx, ex.message
    return dbtx, None

@app.route("/claim_payment/<token>", methods=["GET", "POST"])
def claim_payment(token):
    payment = Payment.from_token(db.session, token)
    if not payment:
        abort(404)
    dbtx = CreatedTransaction.from_txid(db.session, payment.txid)
    if request.method == "POST":
        dbtx, err_msg = process_claim(payment, dbtx)
        if err_msg:
            flash(err_msg, "danger")
    recipient = None
    if dbtx:
        recipient = json.loads(dbtx.json_data)["recipient"]
    return render_template("claim_payment.html", payment=payment, recipient=recipient)

@app.route("/dashboard")
def dashboard():
    data = dashboard_data()
    data["zap_balance"] = from_int_to_user_friendly(data["zap_balance"], 100)
    data["master_waves_balance"] = from_int_to_user_friendly(data["master_waves_balance"], 10**8)
    return render_template("dashboard.html", data=data)

#
# JSON-RPC
#

@jsonrpc.method("status")
def status():
    return dashboard_data()

@jsonrpc.method("getaddress")
def getaddress():
    return {"address": ADDRESS}

@jsonrpc.method("getbalance")
def getbalance():
    path = f"assets/balance/{ADDRESS}/{ASSET_ID}"
    response = requests.get(NODE_BASE_URL + path)
    return response.json()

@jsonrpc.method("gettransaction")
def gettransaction(txid):
    path = f"transactions/info/{txid}"
    response = requests.get(NODE_BASE_URL + path)
    return response.json()

def transfer_asset_txid(tx):
    serialized_data = b'\4' + \
        base58.b58decode(tx["senderPublicKey"]) + \
        (b'\1' + base58.b58decode(tx["assetId"]) if tx["assetId"] else b'\0') + \
        (b'\1' + base58.b58decode(tx["feeAssetId"]) if tx["feeAssetId"] else b'\0') + \
        struct.pack(">Q", tx["timestamp"]) + \
        struct.pack(">Q", tx["amount"]) + \
        struct.pack(">Q", tx["fee"]) + \
        base58.b58decode(tx["recipient"]) + \
        struct.pack(">H", len(tx["attachment"])) + \
        pywaves.crypto.str2bytes(tx["attachment"])
    return utils.txid_from_txdata(serialized_data)

@jsonrpc.method("createtransaction")
def createtransaction(recipient, amount, attachment):
    dbtx = _create_transaction(recipient, amount, attachment)
    db.session.add(dbtx)
    db.session.commit()
    # return txid/state to caller
    return {"txid": dbtx.txid, "state": dbtx.state}

@jsonrpc.method("broadcasttransaction")
def broadcasttransaction(txid):
    dbtx = _broadcast_transaction(txid)
    db.session.add(dbtx)
    db.session.commit()
    # return txid/state to caller
    return {"txid": txid, "state": dbtx.state}

@jsonrpc.method("expiretransactions")
def expiretransactions(above_age=60*60*24):
    count = CreatedTransaction.expire_transactions(db.session, above_age, CTX_CREATED, CTX_EXPIRED)
    db.session.commit()
    return {"count": count}

@jsonrpc.method("validateaddress")
def validateaddress(address):
    if pywaves.validateAddress(address):
        return {"address": address}
    err = OtherError("invalid address", 0)
    raise err

#
# gevent class
#

class ZapWeb():

    def __init__(self, addr="127.0.0.1", port=5000, no_waves=False):
        self.addr = addr
        self.port = port
        self.runloop_greenlet = None
        self.no_waves = no_waves

    def check_wallet(self):
        # check seed has been set
        if not SEED:
            msg = "WALLET_SEED is not set"
            logger.error(msg)
            sys.exit(1)
        # check address object matches our configured address
        global pw_address
        pw_address = pywaves.Address(seed=SEED)
        if pw_address.address.decode() != ADDRESS:
            msg = f"pw_address ({pw_address.address.decode()}) does not match {ADDRESS}"
            logger.error(msg)
            sys.exit(1)

    def start(self, group=None):
        def runloop():
            logger.info("ZapWeb runloop started")

            http_server = WSGIServer((self.addr, self.port), app)
            http_server.serve_forever()

        def start_greenlets():
            logger.info("checking wallet...")
            self.check_wallet()
            logger.info("starting ZapWeb runloop...")
            self.runloop_greenlet.start()

        # create greenlets
        self.runloop_greenlet = gevent.Greenlet(runloop)
        if group != None:
            group.add(self.runloop_greenlet)
        # check node/wallet and start greenlets
        gevent.spawn(start_greenlets)

    def stop(self):
        self.runloop_greenlet.kill()

if __name__ == "__main__":
    # setup logging
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

    zapweb = ZapWeb()
    zapweb.start()

    while 1:
        gevent.sleep(1)

    zapweb.stop()
