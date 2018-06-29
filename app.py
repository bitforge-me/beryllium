#!/usr/bin/python3

import logging

import gevent
import base58

import config
import rpc
import utx

cfg = config.read_cfg()

def setup_logging(level):
    # setup logging
    rpc.logger.setLevel(level)
    utx.logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    rpc.logger.addHandler(ch)
    utx.logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()


def on_transfer_utx(wutx, sig, pubkey, asset_id, timestamp, amount, fee, address, attachment):
    print(f"!transfer!: to {base58.b58encode(address)}, amount {amount}")
    recipient = address
    if recipient == cfg.address:
        invoice_id = utils.extract_invoice_id(attachment)
        #TODO: call configured webhook

if __name__ == "__main__":
    setup_logging(logging.DEBUG)

    zaprpc = rpc.ZapRPC()
    zaprpc.start()
    wutx = utx.WavesUTX(None, on_transfer_utx)
    wutx.start()

    while 1:
        gevent.sleep(1)

    wutx.stop()
    zaprpc.stop()
