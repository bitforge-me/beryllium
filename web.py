#!/usr/bin/python3

import sys
import logging
import json
import datetime
import decimal
from urllib.parse import urlparse

import gevent
from gevent.pywsgi import WSGIServer
from flask import render_template, request, flash, jsonify
from flask_security import roles_accepted
#from flask_jsonrpc import JSONRPC
from flask_jsonrpc.exceptions import OtherError
import requests
import base58
import pywaves
import pyblake2

from app_core import app, db, SERVER_MODE_WAVES, SERVER_MODE_PAYDB
from models import User, WavesTx, WavesTxSig, Proposal, Payment, Topic
import admin
import utils
from fcm import FCM
from web_utils import bad_request, get, get_json_params
import paydb_core

#jsonrpc = JSONRPC(app, "/api")
logger = logging.getLogger(__name__)
fcm = FCM(app.config["FIREBASE_CREDENTIALS"])

SERVER_MODE = app.config["SERVER_MODE"]
DEEP_LINK_SCHEME = app.config["DEEP_LINK_SCHEME"]
if SERVER_MODE == SERVER_MODE_WAVES:
    import tx_utils
    # our pywaves address object
    pw_address = None
    # wave specific config settings
    NODE_BASE_URL = app.config["NODE_BASE_URL"]
    SEED = app.config["WALLET_SEED"]
    ADDRESS = app.config["WALLET_ADDRESS"]
    ASSET_ID = app.config["ASSET_ID"]
    TESTNET = app.config["TESTNET"]
    # paydb blueprint
    from mw_endpoint import mw
    app.register_blueprint(mw, url_prefix='/mw')
elif SERVER_MODE == SERVER_MODE_PAYDB:
    OPERATIONS_ACCOUNT = app.config["OPERATIONS_ACCOUNT"]
    # paydb blueprint
    from paydb_endpoint import paydb
    app.register_blueprint(paydb, url_prefix='/paydb')

def dashboard_data_waves():
    # get balance of local wallet
    url = NODE_BASE_URL + f"/assets/balance/{ADDRESS}/{ASSET_ID}"
    logger.info("requesting {}..".format(url))
    response = requests.get(url)
    try:
        asset_balance = response.json()["balance"]
    except:
        logger.error("failed to parse response")
        asset_balance = "n/a"
    url = NODE_BASE_URL + f"/addresses/balance/{ADDRESS}"
    logger.info("requesting {}..".format(url))
    response = requests.get(url)
    try:
        waves_balance = response.json()["balance"]
    except:
        logger.error("failed to parse response")
        waves_balance = "n/a"
    # get the balance of the main wallet
    url = NODE_BASE_URL + f"/transactions/info/{ASSET_ID}"
    logger.info("requesting {}..".format(url))
    response = requests.get(url)
    try:
        issuer = response.json()["sender"]
        url = NODE_BASE_URL + f"/assets/balance/{issuer}/{ASSET_ID}"
        logger.info("requesting {}..".format(url))
        response = requests.get(url)
        master_asset_balance = response.json()["balance"]
        url = NODE_BASE_URL + f"/addresses/balance/{issuer}"
        logger.info("requesting {}..".format(url))
        response = requests.get(url)
        master_waves_balance = response.json()["balance"]
    except:
        logger.error("failed to parse response")
        issuer = "n/a"
        master_waves_balance = "n/a"
        master_asset_balance = "n/a"
    # return data
    return {"asset_balance": asset_balance, "asset_address": ADDRESS, "waves_balance": waves_balance, \
            "master_asset_balance": master_asset_balance, "master_waves_balance": master_waves_balance, "master_waves_address": issuer, \
            "asset_id": ASSET_ID, \
            "testnet": TESTNET, \
            "premio_qrcode": utils.qrcode_svg_create(ADDRESS), \
            "issuer_qrcode": utils.qrcode_svg_create(issuer), \
            "wavesexplorer": app.config["WAVESEXPLORER"]}

def dashboard_data_paydb():
    premio_stage_balance = -1
    premio_stage_account = app.config['OPERATIONS_ACCOUNT']
    user = User.from_email(db.session, premio_stage_account)
    if user:
        premio_stage_balance = paydb_core.user_balance_from_user(db.session, user)
    total_balance = paydb_core.balance_total(db.session)
    # return data
    return {"premio_stage_balance": premio_stage_balance, "premio_stage_account": premio_stage_account, \
            "total_balance": total_balance}

def from_int_to_user_friendly(val, divisor, decimal_places=4):
    if not isinstance(val, int):
        return val
    val = val / divisor
    return round(val, decimal_places)

def _create_transaction_waves(recipient, amount, attachment):
    # get fee
    path = f"/assets/details/{ASSET_ID}"
    response = requests.get(NODE_BASE_URL + path)
    if response.ok:
        asset_fee = response.json()["minSponsoredAssetFee"]
    else:
        short_msg = "failed to get asset info"
        logger.error(f"{short_msg}: ({response.status_code}, {response.request.method} {response.url}):\n\t{response.text}")
        err = OtherError(short_msg, tx_utils.ERR_FAILED_TO_GET_ASSET_INFO)
        err.data = response.text
        raise err
    if not recipient:
        short_msg = "recipient is null or an empty string"
        logger.error(short_msg)
        err = OtherError(short_msg, tx_utils.ERR_EMPTY_ADDRESS)
        raise err
    if not utils.is_address(recipient):
        short_msg = "recipient is not a valid address"
        logger.error(short_msg)
        err = OtherError(short_msg, tx_utils.ERR_EMPTY_ADDRESS)
        raise err
    recipient = pywaves.Address(recipient)
    asset = pywaves.Asset(ASSET_ID)
    address_data = pw_address.sendAsset(recipient, asset, amount, attachment, feeAsset=asset, txFee=asset_fee)
    signed_tx = json.loads(address_data["api-data"])
    signed_tx["type"] = 4 # sendAsset does not include "type" - https://github.com/PyWaves/PyWaves/issues/131
    # calc txid properly
    txid = tx_utils.tx_to_txid(signed_tx)
    # store tx in db
    dbtx = WavesTx(txid, "transfer", tx_utils.CTX_CREATED, signed_tx["amount"], True, json.dumps(signed_tx))
    return dbtx

def process_proposals():
    with app.app_context():
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
                        utils.email_payment_claim(logger, app.config["ASSET_NAME"], payment, proposal.HOURS_EXPIRY)
                        payment.status = payment.STATE_SENT_CLAIM_LINK
                        db.session.add(payment)
                        logger.info(f"Sent payment claim url to {payment.email}")
                        emails += 1
                    elif payment.mobile:
                        utils.sms_payment_claim(logger, app.config["ASSET_NAME"], payment, proposal.HOURS_EXPIRY)
                        payment.status = payment.STATE_SENT_CLAIM_LINK
                        db.session.add(payment)
                        logger.info(f"Sent payment claim url to {payment.mobile}")
                        sms_messages += 1
                    elif payment.recipient:
                        ##TODO: set status and commit before sending so we cannot send twice
                        raise Exception("not yet implemented")
        db.session.commit()
        #logger.info(f"payment statuses commited")
        return f"done (expired {expired}, emails {emails}, SMS messages {sms_messages})"

#
# Jinja2 filters
#

@app.template_filter()
def int2asset(num):
    num = decimal.Decimal(num)
    return num/100

#
# Flask views
#

@app.route("/")
def index():
    return render_template("index.html")

def process_claim_waves(payment, dbtx, recipient, asset_id):
    if payment.proposal.status != payment.proposal.STATE_AUTHORIZED:
        return dbtx, "payment not authorized"
    if payment.status != payment.STATE_SENT_CLAIM_LINK:
        return dbtx, "payment not authorized"
    # create/get transaction
    if not dbtx:
        if asset_id and asset_id != ASSET_ID:
            return dbtx, "'asset_id' does not match server"
        try:
            dbtx = _create_transaction_waves(recipient, payment.amount, "")
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
        dbtx = tx_utils.broadcast_transaction(db.session, dbtx.txid)
        payment.status = payment.STATE_SENT_FUNDS
        db.session.add(dbtx)
        db.session.commit()
    except OtherError as ex:
        return dbtx, ex.message
    return dbtx, None

def process_claim_paydb(payment, recipient):
    if payment.proposal.status != payment.proposal.STATE_AUTHORIZED:
        return "payment not authorized"
    if payment.status != payment.STATE_SENT_CLAIM_LINK:
        return "payment not authorized"
    # create transaction
    tx, error = paydb_core.tx_transfer_authorized(db.session, OPERATIONS_ACCOUNT, recipient, payment.amount, "")
    if tx:
        payment.txid = tx.token
        payment.status = payment.STATE_SENT_FUNDS
        db.session.add(payment)
        db.session.commit()
        return None
    else:
        return 'claim failed'

@app.route("/claim_payment/<token>", methods=["GET", "POST"])
def claim_payment(token):
    qrcode = None
    url = None
    attachment = None
    payment = Payment.from_token(db.session, token)
    if not payment:
        return bad_request('payment not found', 404)
    now = datetime.datetime.now()
    if now > payment.proposal.date_expiry and payment.status != payment.STATE_SENT_FUNDS:
        return bad_request('expired', 404)

    def render(recipient):
        url_parts = urlparse(request.url)
        url = url_parts._replace(scheme=DEEP_LINK_SCHEME, query='scheme={}'.format(url_parts.scheme)).geturl()
        qrcode_svg = utils.qrcode_svg_create(url)
        return render_template("claim_payment.html", payment=payment, recipient=recipient, qrcode_svg=qrcode_svg, url=url)
    def render_waves(dbtx):
        recipient = None
        if dbtx:
            recipient = dbtx.tx_with_sigs()["recipient"]
        return render(recipient)

    if SERVER_MODE == SERVER_MODE_WAVES:
        dbtx = WavesTx.from_txid(db.session, payment.txid)

    if request.method == "POST":
        content_type = request.content_type
        using_app = content_type.startswith('application/json')
        logger.info("claim_payment: content type - {}, using_app - {}".format(content_type, using_app))
        recipient = ""
        asset_id = ""
        if using_app:
            content = request.get_json(force=True)
            if content is None:
                return bad_request("failed to decode JSON object")
            if SERVER_MODE == SERVER_MODE_WAVES:
                params, err_response = get_json_params(logger, content, ["recipient", "asset_id"])
                if err_response:
                    return err_response
                recipient, asset_id = params
            else: # paydb
                params, err_response = get_json_params(logger, content, ["recipient"])
                if err_response:
                    return err_response
                recipient, = params
        else: # using html form
            try:
                recipient = request.form["recipient"]
            except:
                flash("'recipient' parameter not present", "danger")
                return render_waves(dbtx)
            try:
                asset_id = request.form["asset_id"]
            except:
                pass
        if SERVER_MODE == SERVER_MODE_WAVES:
            dbtx, err_msg = process_claim_waves(payment, dbtx, recipient, asset_id)
        else: # paydb
            err_msg = process_claim_paydb(payment, recipient)
        if err_msg:
            logger.error("claim_payment: {}".format(err_msg))
            if using_app:
                return bad_request(err_msg)
            flash(err_msg, "danger")
    if SERVER_MODE == SERVER_MODE_WAVES:
        return render_waves(dbtx)
    else: # paydb
        return render(None)

@app.route("/dashboard")
@roles_accepted("admin")
def dashboard():
    if SERVER_MODE == SERVER_MODE_WAVES:
        data = dashboard_data_waves()
        data["asset_balance"] = from_int_to_user_friendly(data["asset_balance"], 100)
        data["waves_balance"] = from_int_to_user_friendly(data["waves_balance"], 10**8)
        data["master_asset_balance"] = from_int_to_user_friendly(data["master_asset_balance"], 100)
        data["master_waves_balance"] = from_int_to_user_friendly(data["master_waves_balance"], 10**8)
        return render_template("dashboard_waves.html", data=data)
    else: # paydb
        data = dashboard_data_paydb()
        data["premio_stage_balance"] = from_int_to_user_friendly(data["premio_stage_balance"], 100)
        data["total_balance"] = from_int_to_user_friendly(data["total_balance"], 100)
        return render_template("dashboard_paydb.html", data=data)

@app.route("/push_notifications", methods=["GET", "POST"])
@roles_accepted("admin")
def push_notifications():
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        try:
            if request.form["type"] == "topic":
                topic = request.form["topic"]
                fcm.send_to_topic(topic, title, body)
            else:
                registration_token = request.form["registration_token"]
                fcm.send_to_token(registration_token, title, body)
            flash("sent push noticiation", "success")
        except Exception as e:
            flash("{}".format(str(e.args[0])), "danger")
    topics = Topic.topic_list(db.session)
    return render_template("push_notifications.html", topics=topics)

@app.route("/push_notifications_register", methods=["POST"])
def push_notifications_register():
    content = request.get_json(force=True)
    if content is None:
       return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["registration_token"])
    if err_response:
        return err_response
    registration_token, = params
    topics = Topic.topic_list(db.session)
    fcm.subscribe_to_topics(registration_token, topics)
    return jsonify(dict(result="ok"))

##
## JSON-RPC
##
#
#@jsonrpc.method("status")
#def status():
#    return dashboard_data()
#
#@jsonrpc.method("getaddress")
#def getaddress():
#    return {"address": ADDRESS}
#
#@jsonrpc.method("getbalance")
#def getbalance():
#    path = f"/assets/balance/{ADDRESS}/{ASSET_ID}"
#    response = requests.get(NODE_BASE_URL + path)
#    return response.json()
#
#@jsonrpc.method("gettransaction")
#def gettransaction(txid):
#    path = f"/transactions/info/{txid}"
#    response = requests.get(NODE_BASE_URL + path)
#    return response.json()
#
#@jsonrpc.method("createtransaction")
#def createtransaction(recipient, amount, attachment):
#    dbtx = _create_transaction(recipient, amount, attachment)
#    db.session.add(dbtx)
#    db.session.commit()
#    # return txid/state to caller
#    return {"txid": dbtx.txid, "state": dbtx.state}
#
#@jsonrpc.method("broadcasttransaction")
#def broadcasttransaction(txid):
#    dbtx = _broadcast_transaction(txid)
#    db.session.add(dbtx)
#    db.session.commit()
#    # return txid/state to caller
#    return {"txid": txid, "state": dbtx.state}
#
#@jsonrpc.method("expiretransactions")
#def expiretransactions(above_age=60*60*24):
#    count = WavesTx.expire_transactions(db.session, above_age, CTX_CREATED, CTX_EXPIRED)
#    db.session.commit()
#    return {"count": count}
#
#@jsonrpc.method("validateaddress")
#def validateaddress(address):
#    if pywaves.validateAddress(address):
#        return {"address": address}
#    err = OtherError("invalid address", 0)
#    raise err


#
# gevent class
#

class WebGreenlet():

    def __init__(self, exception_func, addr="0.0.0.0", port=5000):
        self.addr = addr
        self.port = port
        self.runloop_greenlet = None
        self.exception_func = exception_func

    def check_wallet(self):
        # check address object matches our configured address
        global pw_address
        pw_address = pywaves.Address(seed=SEED)
        addr = pw_address.address
        if isinstance(addr, bytes):
            addr = addr.decode()
        if addr != ADDRESS:
            msg = f"pw_address ({addr}) does not match {ADDRESS}"
            logger.error(msg)
            sys.exit(1)

    def start(self):
        def runloop():
            logger.info("WebGreenlet runloop started")
            logger.info(f"WebGreenlet webserver starting (addr: {self.addr}, port: {self.port})")
            http_server = WSGIServer((self.addr, self.port), app)
            http_server.serve_forever()

        def process_proposals_loop():
            while True:
                gevent.spawn(process_proposals)
                gevent.sleep(30)

        def start_greenlets():
            if SERVER_MODE == SERVER_MODE_WAVES:
                logger.info("checking wallet...")
                self.check_wallet()
            logger.info("starting WebGreenlet runloop...")
            self.runloop_greenlet.start()
            self.process_proposals_greenlet.start()

        # create greenlet
        self.runloop_greenlet = gevent.Greenlet(runloop)
        self.process_proposals_greenlet = gevent.Greenlet(process_proposals_loop)
        if self.exception_func:
            self.runloop_greenlet.link_exception(self.exception_func)
        # check node/wallet and start greenlets
        gevent.spawn(start_greenlets)

    def stop(self):
        self.runloop_greenlet.kill()
        self.process_proposals_greenlet.kill()

if __name__ == "__main__":
    # setup logging
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

    web_greenlet = WebGreenlet()
    web_greenlet.start()

    while 1:
        gevent.sleep(1)

    web_greenlet.stop()
