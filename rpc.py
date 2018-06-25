#!/usr/bin/python3

import sys
import time
import logging
import json

import gevent
from gevent.pywsgi import WSGIServer
from flask import Flask
from flask_jsonrpc import JSONRPC
import requests

import config

app = Flask(__name__)
jsonrpc = JSONRPC(app, "/api")
cfg = config.read_cfg()

@jsonrpc.method("balance")
def balance():
    path = f"assets/balance/{cfg.address}/{cfg.asset_id}"
    response = requests.get(cfg.node_http_base_url + path)
    return response.json()

@jsonrpc.method("listtransactions", validate=True)
def listtransactions(invoice_id):
    #TODO
    return None

class ZapRPC():

    def __init__(self, addr="127.0.0.1", port=5000, debug=False):
        self.addr = addr
        self.port = port
        self.debug = debug

    def start(self):
        def runloop():
            logging.info("ZapRPC runloop started")
            # check cfg.address is one of the nodes addresses
            path = f"addresses"
            response = requests.get(cfg.node_http_base_url + path)
            if not cfg.address in response.json():
                logging.error(f"node wallet does not control {cfg.address}")
                sys.exit(1)

            if self.debug:
                app.run(host=self.addr, port=self.port, debug=True)
            else:
                http_server = WSGIServer((self.addr, self.port), app)
                http_server.serve_forever()
        logging.info("spawning ZapRPC runloop...")
        self.g = gevent.spawn(runloop)
        self.g.run()

    def stop(self):
        self.g.kill()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    zaprpc = ZapRPC(debug=True)
    zaprpc.start()

    while 1:
        time.sleep(1)

    zaprpc.stop()
