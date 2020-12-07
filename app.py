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

import web
import utils
from app_core import missing_vital_setting, app, db
from models import user_datastore, User, Role, Category

logger = logging.getLogger(__name__)

# set pywaves to offline mode
pywaves.setOffline()
if app.config["TESTNET"]:
    pywaves.setChain("testnet")

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    web.logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    web.logger.addHandler(ch)
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
    create_role("proposer", "Can propose payments")
    create_role("authorizer", "Can authorize payments")
    create_category("marketing", "")
    create_category("misc", "")
    create_category("testing", "")
    db.session.commit()

    # process commands
    if len(sys.argv) > 1:
        if sys.argv[1] == "add_user":
            add_user(sys.argv[2], sys.argv[3])
        if sys.argv[1] == "add_role":
            add_role(sys.argv[2], sys.argv[3])
    else:
        if missing_vital_setting:
            logger.error('missing vital setting')
            sys.exit(1)
        else:
            logger.info('got all vital settings')

        signal.signal(signal.SIGINT, sigint_handler)

        logger.info("starting greenlets")
        web_greenlet = web.WebGreenlet(g_exception)
        web_greenlet.start()
        while keep_running:
            gevent.sleep(1)
        logger.info("stopping greenlets")
        web_greenlet.stop()
