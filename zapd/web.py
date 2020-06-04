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

import config
from app_core import app, db
from models import Transaction, Block, CreatedTransaction, DashboardHistory, Proposal, Payment, AMWallet, AMDevice
import admin
import utils

cfg = config.read_cfg()
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

def block_height():
    response = get(cfg.node_http_base_url + "blocks/height")
    return response.json()["height"]

def block_at(num):
    response = get(cfg.node_http_base_url + f"blocks/at/{num}")
    return response.json()

def block_chk(blk):
    if not isinstance(blk, dict):
        return False, "blk not dict"
    if "status" in blk and blk["status"] == "error":
        return False, blk["details"]
    if not "signature" in blk:
        return False, "no signature field in blk"
    return True, "all good"

def block_hash(blk):
    height = "unknown"
    if isinstance(blk, int):
        height = blk
        blk = block_at(blk)
    if not "signature" in blk:
        if "height" in blk:
            height = blk["height"]
        blk_json = json.dumps(blk, sort_keys=True, indent=4)
        msg = f"block_hash(): no 'signature' field in block ({height}\n\n{blk_json})"
        logger.error(msg)
        utils.email_death(logger, msg)
        sys.exit(1)
    return blk["signature"]

def dashboard_data():
    # get remote block height
    remote_node = "https://testnode1.wavesnodes.com"
    if not cfg.testnet:
        remote_node = "https://nodes.wavesnodes.com"
    response = get(remote_node + "/blocks/height")
    remote_block_height = response.json()["height"]
    # get locally scanned block height
    scanned_block_height = 0
    last_block = Block.last_block(db.session)
    if last_block:
        scanned_block_height = last_block.num
    # get incomming tx count
    incomming_tx_count = Transaction.count(db.session)
    # get created tx count
    created_tx_count = CreatedTransaction.count(db.session)
    # get balance of local wallet
    path = f"assets/balance/{cfg.address}/{cfg.asset_id}"
    response = requests.get(cfg.node_http_base_url + path)
    zap_balance = response.json()["balance"]
    # get the balance of the main wallet
    path = f"transactions/info/{cfg.asset_id}"
    response = requests.get(cfg.node_http_base_url + path)
    try:
        issuer = response.json()["sender"]
        path = f"addresses/balance/{issuer}"
        response = requests.get(cfg.node_http_base_url + path)
        master_waves_balance = response.json()["balance"]
    except:
        issuer = "n/a"
        master_waves_balance = "n/a"
    # return data
    return {"remote_block_height": remote_block_height, "scanned_block_height": scanned_block_height, \
            "incomming_tx_count": incomming_tx_count, "created_tx_count": created_tx_count, \
            "zap_balance": zap_balance, "zap_address": cfg.address, \
            "master_waves_balance": master_waves_balance, "master_waves_address": issuer, \
            "asset_id": cfg.asset_id, \
            "testnet": cfg.testnet, "remote_node": remote_node}

def from_int_to_user_friendly(val, divisor, decimal_places=4):
    if not isinstance(val, int):
        return val
    val = val / divisor
    return round(val, decimal_places)

def _create_transaction(recipient, amount, attachment):
    # get fee
    path = f"assets/details/{cfg.asset_id}"
    response = requests.get(cfg.node_http_base_url + path)
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
    asset = pywaves.Asset(cfg.asset_id)
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
    response = requests.post(cfg.node_http_base_url + path, headers=headers, data=signed_tx)
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

# App metrics wallet log
@app.route("/am_wallet_log", methods=["POST"])
def wallet_log():
    # get request args
    content = request.json
    app_version = content["app_version"]
    os = content["os"]
    os_version = content["os_version"]
    manufacturer = content["manufacturer"]
    brand = content["brand"]
    device_id = content["device_id"]
    wallet_address = content["wallet_address"]
    # create db objects
    wallet = AMWallet.from_address(db.session, wallet_address)
    dupe = False
    if not wallet:
        wallet = AMWallet(wallet_address)
    else:
        dupe = True
    device = AMDevice(wallet, app_version, os, os_version, manufacturer, brand, device_id)
    db.session.add(wallet)
    db.session.add(device)
    db.session.commit()
    # log error
    if (dupe):
        logger.error(f"found duplicate wallet address: {wallet_address}")
        utils.email_wallet_address_duplicate(logger, wallet_address)

@app.route("/dashboard")
def dashboard():
    history = DashboardHistory.last_week(db.session)
    data = dashboard_data()
    data["zap_balance"] = from_int_to_user_friendly(data["zap_balance"], 100)
    data["master_waves_balance"] = from_int_to_user_friendly(data["master_waves_balance"], 10**8)
    history_convert = []
    for i in range(len(history)):
        item = {}
        item["date"] = history[i].date
        item["zap_balance"] = from_int_to_user_friendly(history[i].zap_balance, 100)
        item["master_waves_balance"] = from_int_to_user_friendly(history[i].master_waves_balance, 10**8)
        history_convert.append(item)
    data["history"] = history_convert
    data["history_mins_since_update"] = 0
    if len(history) > 0:
        data["history_mins_since_update"] = int((time.time() - history[-1].date) / 60)
    return render_template("dashboard.html", data=data)

@app.route("/dashboard/snapshot")
@app.route("/dashboard/snapshot/<cmd>")
def dashboard_snapshot(cmd=None):
    last_entry = DashboardHistory.last_entry(db.session)
    almost_fourhours = 60 * 60 * 4 - 300
    if cmd == "override" or not last_entry or last_entry.date < time.time() - almost_fourhours:
        data = dashboard_data()
        zap_balance = data["zap_balance"]
        master_waves_balance = data["master_waves_balance"]
        if not isinstance(zap_balance, int) or not isinstance(master_waves_balance, int):
            return "not able to get balances"
        history = DashboardHistory(data["incomming_tx_count"], data["created_tx_count"], \
                zap_balance, master_waves_balance)
        db.session.add(history)
        db.session.commit()
        return "ok"
    return "not needed right now"

#
# JSON-RPC
#

@jsonrpc.method("status")
def status():
    return dashboard_data()

@jsonrpc.method("getaddress")
def getaddress():
    return {"address": cfg.address}

@jsonrpc.method("getbalance")
def getbalance():
    path = f"assets/balance/{cfg.address}/{cfg.asset_id}"
    response = requests.get(cfg.node_http_base_url + path)
    return response.json()

@jsonrpc.method("gettransaction")
def gettransaction(txid):
    path = f"transactions/info/{txid}"
    response = requests.get(cfg.node_http_base_url + path)
    return response.json()

@jsonrpc.method("listtransactions")
def listtransactions(invoice_id=None, start_date=0, end_date=0, offset=0, limit=50):
    txs = Transaction.from_invoice_id(db.session, invoice_id, start_date, end_date, offset, limit)
    txs_json = []
    for tx in txs:
        txs_json.append(tx.to_json())
    return txs_json

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
        self.blockloop_greenlet = None
        self.no_waves = no_waves

    def check_wallet(self):
        # check seed has been set
        if not cfg.seed:
            msg = "cfg.seed is not set"
            logger.error(msg)
            utils.email_death(logger, msg)
            sys.exit(1)
        # check address object matches our configured address
        global pw_address
        pw_address = pywaves.Address(seed=cfg.seed)
        if pw_address.address != cfg.address:
            msg = f"pw_address does not match {cfg.address}"
            logger.error(msg)
            utils.email_death(logger, msg)
            sys.exit(1)

    def start(self, group=None):
        def runloop():
            logger.info("ZapWeb runloop started")

            http_server = WSGIServer((self.addr, self.port), app)
            http_server.serve_forever()

        def blockloop():
            logger.info("ZapWeb blockloop started")

            # get last block from the db
            last_block = Block.last_block(db.session)
            if last_block:
                scanned_block_num = last_block.num
            else:
                scanned_block_num = cfg.start_block

            while 1:
                gevent.sleep(5)

                # check for reorgs and invalidate any blocks (and associated txs)
                block = Block.from_number(db.session, scanned_block_num)
                if block:
                    any_reorgs = False
                    blk_hash = block_hash(scanned_block_num)
                    if not blk_hash:
                        msg = f"unable to get hash (from node) for block {scanned_block_num}"
                        logger.error(msg)
                        utils.email_death(logger, msg)
                        sys.exit(1)
                    while blk_hash != block.hash:
                        logger.info("block %d hash does not match current blockchain, must have been reorged" % scanned_block_num)
                        block.set_reorged(db.session)
                        any_reorgs = True
                        # decrement scanned_block_num
                        scanned_block_num -= 1
                        # now do the previous block
                        block = Block.from_number(db.session, scanned_block_num)
                        if not block:
                            msg = f"unable to get hash (from db) for block {scanned_block_num}"
                            logger.error(msg)
                            utils.email_death(logger, msg)
                            sys.exit(1)
                        blk_hash = block_hash(scanned_block_num)
                    if any_reorgs:
                        db.session.commit()
            
                # scan for new blocks
                # use "block_height() - 1" because with the WavesNG protocol the block can have new transactions
                # added until the next block is found
                while block_height() - 1 > scanned_block_num:
                    block = block_at(scanned_block_num + 1)
                    res, reason = block_chk(block)
                    if not res:
                        logger.error(f"failed to get block at {scanned_block_num + 1} ({reason})")
                        break
                    blk_hash = block_hash(block)
                    # check for reorged blocks now reorged *back* into the main chain
                    dbblk = Block.from_hash(db.session, blk_hash)
                    if dbblk:
                        logger.info("block %s (was #%d) now un-reorged" % (blk_hash, dbblk.num))
                        dbblk.num = scanned_block_num + 1
                        dbblk.reorged = False
                    else:
                        dbblk = Block(block["timestamp"], block["height"], blk_hash)
                        db.session.add(dbblk)
                        db.session.flush()
                    # add transactions to db
                    if "transactions" in block:
                        for tx in block["transactions"]:
                            if tx["type"] == 4:
                                recipient = tx["recipient"]
                                asset_id = tx["assetId"]
                                if recipient == cfg.address and asset_id == cfg.asset_id:
                                    txid = tx["id"]
                                    logger.info(f"new tx {txid}")
                                    attachment = tx["attachment"]
                                    if attachment:
                                        attachment = base58.b58decode(attachment)
                                        logger.info(f"    {attachment}")
                                    invoice_id = utils.extract_invoice_id(logger, attachment)
                                    if invoice_id:
                                        logger.info(f"    {invoice_id}")
                                    dbtx = Transaction(txid, tx["sender"], recipient, tx["amount"], attachment, invoice_id, dbblk.id)
                                    db.session.add(dbtx)
                    scanned_block_num = block["height"]
                    logger.debug(f"scanned block {scanned_block_num}")
                    if scanned_block_num % 100 == 0:
                        db.session.commit()
                    gevent.sleep(0)
                db.session.commit()

        def start_greenlets():
            logger.info("checking wallet...")
            self.check_wallet()
            logger.info("starting ZapWeb runloop...")
            self.runloop_greenlet.start()
            if not self.no_waves:
                logger.info("starting ZapWeb blockloop...")
                self.blockloop_greenlet.start()

        # create greenlets
        self.runloop_greenlet = gevent.Greenlet(runloop)
        if not self.no_waves:
            self.blockloop_greenlet = gevent.Greenlet(blockloop)
        if group != None:
            group.add(self.runloop_greenlet)
            if not self.no_waves:
                group.add(self.blockloop_greenlet)
        # check node/wallet and start greenlets
        gevent.spawn(start_greenlets)

    def stop(self):
        self.runloop_greenlet.kill()
        if not self.no_waves:
            self.blockloop_greenlet.kill()

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
