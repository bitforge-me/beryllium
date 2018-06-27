#!/usr/bin/python3

import sys
import logging
import json

import gevent
from gevent.pywsgi import WSGIServer
from flask import Flask
from flask_jsonrpc import JSONRPC
import requests
import base58
import pywaves

import config
from database import db_session, init_db
import db_settings
from models import Transaction, CreatedTransaction

cfg = config.read_cfg()
init_db()
app = Flask(__name__)
jsonrpc = JSONRPC(app, "/api")

# set pywaves to offline mode
pywaves.setOffline()
if cfg.testnet:
    pywaves.setChain("testnet")
# our address object
pw_address = None

@jsonrpc.method("balance")
def balance():
    path = f"assets/balance/{cfg.address}/{cfg.asset_id}"
    response = requests.get(cfg.node_http_base_url + path)
    return response.json()

@jsonrpc.method("listtransactions")
def listtransactions(invoice_id):
    txs = Transaction.from_invoice_id(db_session, invoice_id)
    txs_json = []
    for tx in txs:
        txs_json.append(tx.to_json())
    return txs_json

@jsonrpc.method("createtransaction")
def createtransaction(recipient, amount, attachment):
    recipient = pywaves.Address(recipient)
    signed_tx = pw_address.sendAsset(recipient, pywaves.Asset(cfg.asset_id), amount, attachment)
    signed_tx = json.loads(signed_tx["api-data"])
    #TODO!!!: calc txid properly
    txid = signed_tx["timestamp"]
    # store tx in db
    dbtx = CreatedTransaction(txid, "created", signed_tx["amount"], json.dumps(signed_tx))
    db_session.add(dbtx)
    db_session.commit()
    # return txid/state to caller
    return {"txid": txid, "state": dbtx.state}

@jsonrpc.method("broadcasttransaction")
def broadcasttransaction(txid):
    dbtx = CreatedTransaction.from_txid(db_session, txid)
    signed_tx = json.loads(dbtx.json_data)
    # broadcast
    path = f"assets/broadcast/transfer"
    response = requests.post(cfg.node_http_base_url + path, data=signed_tx)
    if response.ok:
        # update tx in db
        dbtx.state = "broadcast"
    else:
        logging.error(f"broadcast tx: {response.text}")
    db_session.add(dbtx)
    db_session.commit()
    # return txid/state to caller
    return {"txid": txid, "state": dbtx.state}

def block_height():
    response = requests.get(cfg.node_http_base_url + "blocks/height")
    return response.json()["height"]

def block_at(num):
    response = requests.get(cfg.node_http_base_url + f"blocks/at/{num}")
    return response.json()

def extract_invoice_id(attachment):
    data = base58.b58decode(attachment)
    try:
        data = json.loads(data)
        return data["invoice_id"]
    except:
        return None

class ZapRPC():

    def __init__(self, addr="127.0.0.1", port=5000):
        self.addr = addr
        self.port = port

    def start(self):
        # get node addresses
        response = requests.get(cfg.node_http_base_url + "addresses")
        node_addresses = response.json()
        # check cfg.address is one of the nodes addresses
        if not cfg.address in node_addresses:
            logging.error(f"node wallet does not control {cfg.address}")
            sys.exit(1)
        # get private key from our node
        headers = {"X-Api-Key": cfg.node_api_key}
        response = requests.get(cfg.node_http_base_url + "wallet/seed", headers=headers)
        if not response.ok:
            logging.error(f"Wallet seed request: {response.text}")
            sys.exit(1)
        else:
            # create our address object for creating transactions
            wallet_seed = response.json()["seed"]
            global pw_address
            pw_address = pywaves.Address(seed=wallet_seed)
            # check address object matches our configured address
            if not pw_address.address != cfg.address:
                logging.error(f"pw_address does not match {cfg.address}")
                sys.exit(1)

        def runloop():
            logging.info("ZapRPC runloop started")

            http_server = WSGIServer((self.addr, self.port), app)
            http_server.serve_forever()

        def blockloop():
            logging.info("ZapRPC blockloop started")

            scanned_block_num = db_settings.get_scanned_block_num(cfg.start_block)
            while 1:
                gevent.sleep(5)
                while block_height() > scanned_block_num:
                    block = block_at(scanned_block_num + 1)
                    for tx in block["transactions"]:
                        if tx["type"] == 4:
                            recipient = tx["recipient"]
                            if recipient == cfg.address:
                                txid = tx["id"]
                                logging.info(f"new tx {txid}")
                                attachment = tx["attachment"]
                                invoice_id = extract_invoice_id(attachment)
                                dbtx = Transaction(txid, tx["sender"], recipient, tx["amount"], attachment, invoice_id, block["height"])
                                db_session.add(dbtx)
                    scanned_block_num = block["height"]
                    logging.debug(f"scanned block {scanned_block_num}")
                    if scanned_block_num % 100 == 0:
                        db_settings.set_scanned_block_num(db_session, scanned_block_num)
                        db_session.commit()
                    gevent.sleep(0)
                db_session.commit()

        logging.info("spawning ZapRPC runloop...")
        self.runloop_greenlet = gevent.spawn(runloop)
        logging.info("spawning ZapRPC blockloop...")
        self.blockloop_greenlet = gevent.spawn(blockloop)
        gevent.sleep(0)

    def stop(self):
        self.runloop_greenlet.kill()
        self.blockloop_greenlet.kill()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    zaprpc = ZapRPC()
    zaprpc.start()

    while 1:
        gevent.sleep(1)

    zaprpc.stop()
