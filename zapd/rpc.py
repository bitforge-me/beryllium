#!/usr/bin/python3

import sys
import logging
import json
import struct

import gevent
from gevent.pywsgi import WSGIServer
from flask import Flask, render_template
from flask_jsonrpc import JSONRPC
from flask_jsonrpc.exceptions import OtherError
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import base58
import pywaves
import pyblake2

import config
from database import db_session, init_db
from models import Transaction, Block, CreatedTransaction
import utils

cfg = config.read_cfg()
init_db()
app = Flask(__name__)
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

def dashboard_data():
    # get remote block height
    remote_node = "https://testnode1.wavesnodes.com"
    if not cfg.testnet:
        remote_node = "https://nodes.wavesnodes.com"
    response = get(remote_node + "/blocks/height")
    remote_block_height = response.json()["height"]
    # get locally scanned block height
    scanned_block_height = 0
    last_block = Block.last_block(db_session)
    if last_block:
        scanned_block_height = last_block.num
    # get incomming tx count
    incomming_tx_count = Transaction.count(db_session)
    # get created tx count
    created_tx_count = CreatedTransaction.count(db_session)
    # get balance of local wallet
    path = f"assets/balance/{cfg.address}/{cfg.asset_id}"
    response = requests.get(cfg.node_http_base_url + path)
    zap_balance = response.json()["balance"]
    # get the balance of the main wallet
    path = f"transactions/info/{cfg.asset_id}"
    response = requests.get(cfg.node_http_base_url + path)
    issuer = response.json()["sender"]
    path = f"addresses/balance/{issuer}"
    response = requests.get(cfg.node_http_base_url + path)
    master_waves_balance = response.json()["balance"]
    # return data
    return {"remote_block_height": remote_block_height, "scanned_block_height": scanned_block_height, \
            "incomming_tx_count": incomming_tx_count, "created_tx_count": created_tx_count, \
            "zap_balance": zap_balance, "master_waves_balance": master_waves_balance}

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", data=dashboard_data())

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
    txs = Transaction.from_invoice_id(db_session, invoice_id, start_date, end_date, offset, limit)
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
    recipient = pywaves.Address(recipient)
    asset = pywaves.Asset(cfg.asset_id)
    address_data = pw_address.sendAsset(recipient, asset, amount, attachment, feeAsset=asset, txFee=asset_fee)
    signed_tx = json.loads(address_data["api-data"])
    # calc txid properly
    txid = transfer_asset_txid(signed_tx)
    # store tx in db
    dbtx = CreatedTransaction(txid, CTX_CREATED, signed_tx["amount"], address_data["api-data"])
    db_session.add(dbtx)
    db_session.commit()
    # return txid/state to caller
    return {"txid": txid, "state": dbtx.state}

@jsonrpc.method("broadcasttransaction")
def broadcasttransaction(txid):
    dbtx = CreatedTransaction.from_txid(db_session, txid)
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
        db_session.add(dbtx)
        db_session.commit()
    else:
        short_msg = "failed to broadcast"
        logger.error(f"{short_msg}: ({response.status_code}, {response.request.method} {response.url}):\n\t{response.text}")
        err = OtherError(short_msg, ERR_FAILED_TO_BROADCAST)
        err.data = response.text
        raise err
    # return txid/state to caller
    return {"txid": txid, "state": dbtx.state}

@jsonrpc.method("expiretransactions")
def expiretransactions(above_age=60*60*24):
    count = CreatedTransaction.expire_transactions(db_session, above_age, CTX_CREATED, CTX_EXPIRED)
    db_session.commit()
    return {"count": count}

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

def block_hash(blk):
    height = "unknown"
    if isinstance(blk, int):
        height = blk
        blk = block_at(blk)
    if not "signature" in blk:
        if "height" in blk:
            height = blk["height"]
        blk_json = json.dumps(blk, sort_keys=True, indent=4)
        msg = f"block_hash(): no 'signature' field in block ({height}\n\n{blk_json}"
        logger.error(msg)
        utils.email_death(logger, msg)
        sys.exit(1)
    return blk["signature"]

class ZapRPC():

    def __init__(self, addr="127.0.0.1", port=5000):
        self.addr = addr
        self.port = port
        self.runloop_greenlet = None
        self.blockloop_greenlet = None

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
            logger.info("ZapRPC runloop started")

            http_server = WSGIServer((self.addr, self.port), app)
            http_server.serve_forever()

        def blockloop():
            logger.info("ZapRPC blockloop started")

            # get last block from the db
            last_block = Block.last_block(db_session)
            if last_block:
                scanned_block_num = last_block.num
            else:
                scanned_block_num = cfg.start_block

            while 1:
                gevent.sleep(5)

                # check for reorgs and invalidate any blocks (and associated txs)
                block = Block.from_number(db_session, scanned_block_num)
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
                        block.set_reorged(db_session)
                        any_reorgs = True
                        # decrement scanned_block_num
                        scanned_block_num -= 1
                        # now do the previous block
                        block = Block.from_number(db_session, scanned_block_num)
                        if not block:
                            msg = f"unable to get hash (from db) for block {scanned_block_num}"
                            logger.error(msg)
                            utils.email_death(logger, msg)
                            sys.exit(1)
                        blk_hash = block_hash(scanned_block_num)
                    if any_reorgs:
                        db_session.commit()
            
                # scan for new blocks
                # use "block_height() - 1" because with the WavesNG protocol the block can have new transactions
                # added until the next block is found
                while block_height() - 1 > scanned_block_num:
                    block = block_at(scanned_block_num + 1)
                    blk_hash = block_hash(block)
                    # check for reorged blocks now reorged *back* into the main chain
                    dbblk = Block.from_hash(db_session, blk_hash)
                    if dbblk:
                        self.logger.info("block %s (was #%d) now un-reorged" % (blk_hash.hex(), dbblk.num))
                        dbblk.num = block_num
                        dbblk.reorged = False
                    else:
                        dbblk = Block(block["timestamp"], block["height"], blk_hash)
                        db_session.add(dbblk)
                        db_session.flush()
                    # add transactions to db
                    if "transactions" in block:
                        for tx in block["transactions"]:
                            if tx["type"] == 4:
                                recipient = tx["recipient"]
                                if recipient == cfg.address:
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
                                    db_session.add(dbtx)
                    scanned_block_num = block["height"]
                    logger.debug(f"scanned block {scanned_block_num}")
                    if scanned_block_num % 100 == 0:
                        db_session.commit()
                    gevent.sleep(0)
                db_session.commit()

        def start_greenlets():
            logger.info("checking wallet...")
            self.check_wallet()
            logger.info("starting ZapRPC runloop...")
            self.runloop_greenlet.start()
            logger.info("starting ZapRPC blockloop...")
            self.blockloop_greenlet.start()

        # create greenlets
        self.runloop_greenlet = gevent.Greenlet(runloop)
        self.blockloop_greenlet = gevent.Greenlet(blockloop)
        if group != None:
            group.add(self.runloop_greenlet)
            group.add(self.blockloop_greenlet)
        # check node/wallet and start greenlets
        gevent.spawn(start_greenlets)

    def stop(self):
        self.runloop_greenlet.kill()
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

    zaprpc = ZapRPC()
    zaprpc.start()

    while 1:
        gevent.sleep(1)

    zaprpc.stop()
