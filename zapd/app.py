#!/usr/bin/python3

import os
import sys
import logging
import signal

import gevent
import gevent.pool
import base58
import pywaves
from flask_security.utils import encrypt_password

import config
import web
import utx
import utils
from app_core import app, db
from models import user_datastore, User, Role, Category

cfg = config.read_cfg()
logger = logging.getLogger(__name__)

# set pywaves to offline mode
pywaves.setOffline()
if cfg.testnet:
    pywaves.setChain("testnet")

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    web.logger.setLevel(level)
    utx.logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    web.logger.addHandler(ch)
    utx.logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

def add_user(email, password):
    with app.app_context():
        user = User.from_email(db.session, email)
        if user:
            #logger.error("user already exists")
            #return
            user.password = encrypt_password(password)
        else:
            user = user_datastore.create_user(email=email, password=encrypt_password(password))
        db.session.commit()

def create_role(name, desc):
    role = Role.from_name(db.session, name)
    if not role:
        role = Role(name=name, description=desc)
    else:
        role.description = desc
    db.session.add(role)
    return role

def create_category(name, desc):
    category = Category.from_name(db.session, name)
    if not category:
        category = Category(name=name, description=desc)
    else:
        category.description = desc
    db.session.add(category)
    return category

def add_role(email, role_name):
    with app.app_context():
        user = User.from_email(db.session, email)
        if not user:
            logger.error("user does not exist")
            return
        role = create_role(role_name, None)
        if role not in user.roles:
            user.roles.append(role)
        else:
            logger.info("user already has role")
        db.session.commit()

def on_transfer_utx(wutx, txid, sig, pubkey, asset_id, timestamp, amount, fee, recipient, attachment):
    recipient = base58.b58encode(recipient)
    try:
        asset_id = base58.b58encode(asset_id)
    except TypeError:
        pass
    #logger.info(f"!transfer!: txid {txid}, recipient {recipient}, amount {amount}, attachment {attachment}")
    if recipient == cfg.address and asset_id == cfg.asset_id:
        # create message
        sender = utils.address_from_public_key(pubkey)
        invoice_id = utils.extract_invoice_id(logger, attachment)
        msg, sig = utils.create_signed_payment_notification(txid, timestamp, recipient, sender, amount, invoice_id)
        utils.call_webhook(logger, msg, sig)

def sigint_handler(signum, frame):
    global keep_running
    logger.warning("SIGINT caught, attempting to exit gracefully")
    keep_running = False

def g_exception(g):
    try:
        g.get()
    except Exception as e:
        import traceback
        stack_trace = traceback.format_exc()
        msg = f"{e}\n---\n{stack_trace}"
        utils.email_exception(logger, msg)

keep_running = True
if __name__ == "__main__":
    setup_logging(logging.DEBUG)

    # create tables
    db.create_all()
    create_role("admin", "super user")
    create_role("proposer", "Can propose zap payments")
    create_role("authorizer", "Can authorize zap payments")
    create_category("marketing", "")
    create_category("misc", "")
    create_category("customer incentive", "")
    create_category("staff incentive", "")
    create_category("merchant incentive", "")
    create_category("testing", "")
    db.session.commit()

    # process commands
    if len(sys.argv) > 1:
        if sys.argv[1] == "add_user":
            add_user(sys.argv[2], sys.argv[3])
        if sys.argv[1] == "add_role":
            add_role(sys.argv[2], sys.argv[3])
    else:
        signal.signal(signal.SIGINT, sigint_handler)

        no_waves = os.getenv("NO_WAVES")
        logger.info("starting greenlets")
        group = gevent.pool.Group()
        greenlet_count = 0
        zapweb = web.ZapWeb(no_waves=no_waves)
        zapweb.start(group)
        greenlet_count += 1 if no_waves else 2
        wutx = None
        if not no_waves:
            port = 6863
            if not cfg.testnet:
                port = 6868
            wutx = utx.WavesUTX(None, on_transfer_utx, port=port, testnet=cfg.testnet)
            wutx.start(group)
            greenlet_count += 1
        logger.info("main loop")
        sent_start_email = False
        for g in group:
            g.link_exception(g_exception)
        while keep_running:
            gevent.sleep(1)
            # check if any essential greenlets are dead
            if len(group) < greenlet_count:
                msg = "one of our greenlets is dead X("
                logger.error(msg)
                utils.email_death(logger, msg)
                break
            # send start email when all essential greenlets are started
            if not sent_start_email:
                send_start_email = True
                for g in group:
                    if not g.started:
                        send_start_email = False
                if send_start_email:
                    sent_start_email = True
                    msg = "our greenlets have started :)"
                    logger.info(msg)
                    utils.email_alive(logger, msg)
        logger.info("stopping greenlets")
        if wutx:
            wutx.stop()
        zapweb.stop()
