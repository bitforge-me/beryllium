#!/usr/bin/python3

import sys
import logging
import json
import struct
import time
import datetime
import decimal
import base64
import io
from urllib.parse import urlparse

import gevent
from gevent.pywsgi import WSGIServer
from flask import Flask, render_template, request, flash, jsonify
from flask_security import current_user, roles_accepted
#from flask_jsonrpc import JSONRPC
from flask_jsonrpc.exceptions import OtherError
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import base58
import pywaves
import pyblake2
import qrcode
import qrcode.image.svg

from app_core import app, db
from models import TokenTx, TxSig, Proposal, Payment, Topic
import admin
import utils
import tx_utils
from fcm import FCM

#jsonrpc = JSONRPC(app, "/api")
logger = logging.getLogger(__name__)
fcm = FCM(app.config["FIREBASE_CREDENTIALS"])

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

NODE_BASE_URL = app.config["NODE_BASE_URL"]
SEED = app.config["WALLET_SEED"]
ADDRESS = app.config["WALLET_ADDRESS"]
ASSET_ID = app.config["ASSET_ID"]

#
# helper functions
#

def bad_request(message, code=400):
    response = jsonify({'message': message})
    response.status_code = code
    return response

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

def dashboard_data():
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
            "testnet": app.config["TESTNET"], \
            "premio_qrcode": qrcode_svg_create(ADDRESS), \
            "issuer_qrcode": qrcode_svg_create(issuer), \
            "wavesexplorer": app.config["WAVESEXPLORER"]}

def from_int_to_user_friendly(val, divisor, decimal_places=4):
    if not isinstance(val, int):
        return val
    val = val / divisor
    return round(val, decimal_places)

def tx_to_txid(tx):
    logger.info("tx_to_txid - tx: {}".format(tx))
    tx_utils.tx_init_chain_id(app.config["TESTNET"])
    return utils.txid_from_txdata(tx_utils.tx_serialize(tx))

def _create_transaction(recipient, amount, attachment):
    # get fee
    path = f"/assets/details/{ASSET_ID}"
    response = requests.get(NODE_BASE_URL + path)
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
    asset = pywaves.Asset(ASSET_ID)
    address_data = pw_address.sendAsset(recipient, asset, amount, attachment, feeAsset=asset, txFee=asset_fee)
    signed_tx = json.loads(address_data["api-data"])
    signed_tx["type"] = 4 # sendAsset does not include "type" - https://github.com/PyWaves/PyWaves/issues/131
    # calc txid properly
    txid = tx_to_txid(signed_tx)
    # store tx in db
    dbtx = TokenTx(txid, "transfer", CTX_CREATED, signed_tx["amount"], True, json.dumps(signed_tx))
    return dbtx

def _broadcast_transaction(txid):
    dbtx = TokenTx.from_txid(db.session, txid)
    if not dbtx:
        raise OtherError("transaction not found", ERR_NO_TXID)
    if dbtx.state == CTX_EXPIRED:
        raise OtherError("transaction expired", ERR_TX_EXPIRED)
    signed_tx = dbtx.tx_with_sigs()
    logger.info("broadcasting tx: {}".format(signed_tx))
    # broadcast
    logger.debug(f"requesting broadcast of tx:\n\t{signed_tx}")
    path = f"/transactions/broadcast"
    headers = {"Content-Type": "application/json"}
    response = requests.post(NODE_BASE_URL + path, headers=headers, data=json.dumps(signed_tx))
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

def qrcode_svg_create(data, box_size=10):
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(data, image_factory=factory, box_size=box_size)
    output = io.BytesIO()
    img.save(output)
    svg = output.getvalue().decode('utf-8')
    return svg

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
                    elif payment.wallet_address:
                        ##TODO: set status and commit before sending so we cannot send twice
                        raise Exception("not yet implemented")
        db.session.commit()
        logger.info(f"payment statuses commited")
        return f"done (expired {expired}, emails {emails}, SMS messages {sms_messages})"

def _get_json_params(content, param_names):
    param_values = []
    param_name = ''
    try:
        for param in param_names:
            param_name = param
            param_values.append(content[param])
    except Exception as e:
        logger.error(f"'{param_name}' not found")
        logger.error(e)
        return param_values, bad_request(f"'{param_name}' not found")
    return param_values, None

#
# Jinja2 filters
#

@app.template_filter()
def int2asset(num):
    num = decimal.Decimal(num)
    return num/100

@app.context_processor
def inject_config_qrcode_svg():
    url_parts = urlparse(request.url)
    url = url_parts._replace(scheme="premiomwlink", path="/config").geturl()
    qrcode_svg = qrcode_svg_create(url, box_size=6)
    return dict(config_url=url, config_qrcode_svg=qrcode_svg)

#
# Flask views
#

@app.route("/")
def index():
    return render_template("index.html")

def process_claim(payment, dbtx, recipient, asset_id):
    if payment.proposal.status != payment.proposal.STATE_AUTHORIZED:
        return dbtx, "payment not authorized"
    if payment.status != payment.STATE_SENT_CLAIM_LINK:
        return dbtx, "payment not authorized"
    # create/get transaction
    if not dbtx:
        if asset_id and asset_id != app.config["ASSET_ID"]:
            return dbtx, "'asset_id' does not match server"
        try:
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
    qrcode = None
    url = None
    attachment = None
    payment = Payment.from_token(db.session, token)
    if not payment:
        return bad_request('payment not found', 404)
    dbtx = TokenTx.from_txid(db.session, payment.txid)

    def render(dbtx):
        recipient = None
        if dbtx:
            recipient = dbtx.tx_with_sigs()["recipient"]
        url_parts = urlparse(request.url)
        url = url_parts._replace(scheme="premiostagelink").geturl()
        qrcode_svg = qrcode_svg_create(url)
        return render_template("claim_payment.html", payment=payment, recipient=recipient, qrcode_svg=qrcode_svg, url=url)

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
            params, err_response = _get_json_params(content, ["recipient", "asset_id"])
            if err_response:
                return err_response
            recipient, asset_id = params
        else: # using html form
            try:
                recipient = request.form["recipient"]
            except:
                flash("'recipient' parameter not present", "danger")
                return render(dbtx)
            try:
                asset_id = request.form["asset_id"]
            except:
                pass
        dbtx, err_msg = process_claim(payment, dbtx, recipient, asset_id)
        if err_msg:
            logger.error("claim_payment: {}".format(err_msg))
            if using_app:
                return bad_request(err_msg)
            flash(err_msg, "danger")
    return render(dbtx)

@app.route("/dashboard")
@roles_accepted("admin")
def dashboard():
    data = dashboard_data()
    data["asset_balance"] = from_int_to_user_friendly(data["asset_balance"], 100)
    data["waves_balance"] = from_int_to_user_friendly(data["waves_balance"], 10**8)
    data["master_asset_balance"] = from_int_to_user_friendly(data["master_asset_balance"], 100)
    data["master_waves_balance"] = from_int_to_user_friendly(data["master_waves_balance"], 10**8)
    return render_template("dashboard.html", data=data)

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
    params, err_response = _get_json_params(content, ["registration_token"])
    if err_response:
        return err_response
    registration_token, = params
    topics = Topic.topic_list(db.session)
    fcm.subscribe_to_topics(registration_token, topics)
    return jsonify(dict(result="ok"))

@app.route("/config")
def config():
    return jsonify(dict(asset_id=app.config["ASSET_ID"], asset_name=app.config["ASSET_NAME"], testnet=app.config["TESTNET"], tx_signers=app.config["TX_SIGNERS"], tx_types=tx_utils.TYPES))

@app.route("/tx_link/<txid>")
def tx_link(txid):
    url_parts = urlparse(request.url)
    url = url_parts._replace(scheme="premiomwlink", path="/txid/" + txid).geturl()
    qrcode_svg = qrcode_svg_create(url)
    return render_template("tx_link.html", qrcode_svg=qrcode_svg, url=url)

@app.route("/tx_create", methods=["POST"])
def tx_create():
    tx_utils.tx_init_chain_id(app.config["TESTNET"])

    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = _get_json_params(content, ["type", "timestamp"])
    if err_response:
        return err_response
    type, timestamp = params
    if not type in tx_utils.TYPES:
        return bad_request("'type' not valid")
    pubkey = app.config["ASSET_MASTER_PUBKEY"]
    address = tx_utils.generate_address(pubkey)
    asset_id = app.config["ASSET_ID"]
    amount = 0
    if type == "transfer":
        fee = tx_utils.get_fee(app.config["NODE_BASE_URL"], tx_utils.DEFAULT_TX_FEE, address, None)
        params, err_response = _get_json_params(content, ["recipient", "amount"])
        if err_response:
            return err_response
        recipient, amount = params
        tx = tx_utils.transfer_asset_payload(address, pubkey, None, recipient, asset_id, amount, fee=fee, timestamp=timestamp)
    elif type == "issue":
        fee = tx_utils.get_fee(app.config["NODE_BASE_URL"], tx_utils.DEFAULT_ASSET_FEE, address, None)
        params, err_response = _get_json_params(content, ["asset_name", "asset_description", "amount"])
        if err_response:
            return err_response
        asset_name, asset_description, amount = params
        tx = tx_utils.issue_asset_payload(address, pubkey, None, asset_name, asset_description, amount, decimals=2, reissuable=True, fee=fee, timestamp=timestamp)
    elif type == "reissue":
        fee = tx_utils.get_fee(app.config["NODE_BASE_URL"], tx_utils.DEFAULT_ASSET_FEE, address, None)
        params, err_response = _get_json_params(content, ["amount"])
        if err_response:
            return err_response
        amount, = params
        tx = tx_utils.reissue_asset_payload(address, pubkey, None, asset_id, amount, reissuable=True, fee=fee, timestamp=timestamp)
    elif type == "sponsor":
        fee = tx_utils.get_fee(app.config["NODE_BASE_URL"], tx_utils.DEFAULT_SPONSOR_FEE, address, None)
        params, err_response = _get_json_params(content, ["asset_fee"])
        if err_response:
            return err_response
        asset_fee, = params
        amount = asset_fee
        tx = tx_utils.sponsor_payload(address, pubkey, None, asset_id, asset_fee, fee=fee, timestamp=timestamp)
    elif type == "setscript":
        fee = tx_utils.get_fee(app.config["NODE_BASE_URL"], tx_utils.DEFAULT_SCRIPT_FEE, address, None)
        params, err_response = _get_json_params(content, ["script"])
        if err_response:
            return err_response
        script, = params
        tx = tx_utils.set_script_payload(address, pubkey, None, script, fee=fee, timestamp=timestamp)
    else:
        return bad_request("invalid type")

    txid = tx_to_txid(tx)
    dbtx = TokenTx.from_txid(db.session, txid)
    if dbtx:
        return bad_request("txid already exists")
    dbtx = TokenTx(txid, type, CTX_CREATED, amount, False, json.dumps(tx))
    db.session.add(dbtx)
    db.session.commit()
    return jsonify(dict(txid=txid, state=CTX_CREATED, tx=tx))

@app.route("/tx_status", methods=["POST"])
def tx_status():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = _get_json_params(content, ["txid"])
    if err_response:
        return err_response
    txid, = params
    dbtx = TokenTx.from_txid(db.session, txid)
    if not dbtx:
        return bad_request('tx not found', 404)
    tx = dbtx.tx_with_sigs()
    return jsonify(dict(txid=txid, state=dbtx.state, tx=tx))

@app.route("/tx_serialize", methods=["POST"])
def tx_serialize():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = _get_json_params(content, ["tx"])
    if err_response:
        return err_response
    tx, = params
    if not "type" in tx:
        return bad_request("tx does not contain 'type' field")
    tx_serialized = tx_utils.tx_serialize(tx)
    res = {"bytes": base64.b64encode(tx_serialized).decode("utf-8", "ignore")}
    return jsonify(res)

@app.route("/tx_signature", methods=["POST"])
def tx_signature():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = _get_json_params(content, ["txid", "signer_index", "signature"])
    if err_response:
        return err_response
    txid, signer_index, signature = params
    dbtx = TokenTx.from_txid(db.session, txid)
    if not dbtx:
        return bad_request('tx not found', 404)
    sig = TxSig(dbtx, signer_index, signature)
    db.session.add(sig)
    db.session.commit()
    tx = dbtx.tx_with_sigs()
    return jsonify(dict(txid=txid, state=dbtx.state, tx=tx))

@app.route("/tx_broadcast", methods=["POST"])
def tx_broadcast():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = _get_json_params(content, ["txid"])
    if err_response:
        return err_response
    txid, = params
    dbtx = TokenTx.from_txid(db.session, txid)
    if not dbtx:
        return bad_request('tx not found', 404)
    tx = dbtx.tx_with_sigs()
    error = ""
    # broadcast transaction
    try:
        dbtx = _broadcast_transaction(dbtx.txid)
        db.session.add(dbtx)
        db.session.commit()
    except OtherError as ex:
        error = ex.message
        if hasattr(ex, 'data'):
            error = "{} - {}".format(ex.message, ex.data)
    return jsonify(dict(txid=txid, state=dbtx.state, tx=tx, error=error))

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
#    count = TokenTx.expire_transactions(db.session, above_age, CTX_CREATED, CTX_EXPIRED)
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
