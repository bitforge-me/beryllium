#!/usr/bin/python3

import logging
import hmac
import base64

import gevent
from gevent.pywsgi import WSGIServer
from flask import Flask, request, abort

import config

app = Flask(__name__)
logger = logging.getLogger(__name__)
cfg = config.read_cfg()

@app.route("/webhook_test", methods=("GET", "POST"))
def webhook_test():
    if request.method == "GET":
        return "ok"
    sig = request.headers.get("Signature")
    msg = request.get_data(cache=False, as_text=True)
    print(f"Signature is {sig}")
    sig = base64.b64decode(sig)
    sig_ours = hmac.HMAC(cfg.webhook_key.encode(), msg.encode(), "sha256").digest()
    if not hmac.compare_digest(sig, sig_ours):
        abort(401)
    print(f"Msg:\n\t{msg}")
    return "ok"

class WebhookTest():

    def __init__(self, addr="127.0.0.1", port=5001):
        self.addr = addr
        self.port = port

    def start(self):
        def runloop():
            logger.info("WebhookTest runloop started")

            http_server = WSGIServer((self.addr, self.port), app)
            http_server.serve_forever()

        logger.info("spawning WebhookTest runloop...")
        self.runloop_greenlet = gevent.spawn(runloop)
        gevent.sleep(0)

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

    wht = WebhookTest()
    wht.start()

    while 1:
        gevent.sleep(1)

    wht.stop()
