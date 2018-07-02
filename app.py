#!/usr/bin/python3

import logging

import gevent
import base58
import pywaves

import config
import rpc
import utx
import utils

cfg = config.read_cfg()
logger = logging.getLogger(__name__)

# set pywaves to offline mode
pywaves.setOffline()
if cfg.testnet:
    pywaves.setChain("testnet")

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    rpc.logger.setLevel(level)
    utx.logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    rpc.logger.addHandler(ch)
    utx.logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()


def on_transfer_utx(wutx, txid, sig, pubkey, asset_id, timestamp, amount, fee, recipient, attachment):
    recipient = base58.b58encode(recipient)
    logger.info(f"!transfer!: txid {txid}, recipient {recipient}, amount {amount}, attachment {attachment}")
    if recipient == cfg.address:
        # create message
        from_ = utils.address_from_public_key(pubkey)
        invoice_id = utils.extract_invoice_id(logger, attachment)
        msg, sig = utils.create_signed_payment_notification(txid, timestamp, recipient, from_, amount, invoice_id)
        utils.call_webhook(logger, msg, sig)

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
