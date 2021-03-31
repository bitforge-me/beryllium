import logging
import json
import base64
from urllib.parse import urlparse

from flask import Blueprint, render_template, request, jsonify
from flask_jsonrpc.exceptions import OtherError

from app_core import app, db
from models import WavesTx, WavesTxSig
import utils
import tx_utils
from web_utils import bad_request, get_json_params

logger = logging.getLogger(__name__)
mw = Blueprint('mw', __name__, template_folder='templates')

# wave specific config settings
NODE_BASE_URL = app.config["NODE_BASE_URL"]
SEED = app.config["WALLET_SEED"]
ADDRESS = app.config["WALLET_ADDRESS"]
ASSET_ID = app.config["ASSET_ID"]
ASSET_NAME = app.config["ASSET_NAME"]
TESTNET = app.config["TESTNET"]
TX_SIGNERS = app.config["TX_SIGNERS"]
ASSET_MASTER_PUBKEY = app.config["ASSET_MASTER_PUBKEY"]

#
# Jinja2 filters
#

@app.context_processor
def inject_config_qrcode_svg():
    url_parts = urlparse(request.url)
    url = url_parts._replace(scheme="premiomwlink", path="/config").geturl()
    qrcode_svg = utils.qrcode_svg_create(url, box_size=6)
    return dict(mw_config_url=url, mw_config_qrcode_svg=qrcode_svg)

#
# Flask views
#

@app.route("/config")
def config():
    return jsonify(dict(asset_id=ASSET_ID, asset_name=ASSET_NAME, testnet=TESTNET, tx_signers=TX_SIGNERS, tx_types=tx_utils.TYPES))

@app.route("/tx_link/<txid>")
def tx_link(txid):
    url_parts = urlparse(request.url)
    url = url_parts._replace(scheme="premiomwlink", path="/txid/" + txid).geturl()
    qrcode_svg = utils.qrcode_svg_create(url)
    return render_template("mw/tx_link.html", qrcode_svg=qrcode_svg, url=url)

@app.route("/tx_create", methods=["POST"])
def tx_create():
    tx_utils.tx_init_chain_id(TESTNET)

    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["type", "timestamp"])
    if err_response:
        return err_response
    type_, timestamp = params
    if not type_ in tx_utils.TYPES:
        return bad_request("'type' not valid")
    pubkey = ASSET_MASTER_PUBKEY
    address = tx_utils.generate_address(pubkey)
    amount = 0
    if type_ == "transfer":
        fee = tx_utils.get_fee(NODE_BASE_URL, tx_utils.DEFAULT_TX_FEE, address, None)
        params, err_response = get_json_params(logger, content, ["recipient", "amount"])
        if err_response:
            return err_response
        recipient, amount = params
        tx = tx_utils.transfer_asset_payload(address, pubkey, None, recipient, ASSET_ID, amount, "", None, fee, timestamp)
    elif type_ == "issue":
        fee = tx_utils.get_fee(NODE_BASE_URL, tx_utils.DEFAULT_ASSET_FEE, address, None)
        params, err_response = get_json_params(logger, content, ["asset_name", "asset_description", "amount"])
        if err_response:
            return err_response
        asset_name, asset_description, amount = params
        tx = tx_utils.issue_asset_payload(address, pubkey, None, asset_name, asset_description, amount, None, 2, True, fee, timestamp)
    elif type_ == "reissue":
        fee = tx_utils.get_fee(NODE_BASE_URL, tx_utils.DEFAULT_ASSET_FEE, address, None)
        params, err_response = get_json_params(logger, content, ["amount"])
        if err_response:
            return err_response
        amount, = params
        tx = tx_utils.reissue_asset_payload(address, pubkey, None, ASSET_ID, amount, True, fee, timestamp)
    elif type_ == "sponsor":
        fee = tx_utils.get_fee(NODE_BASE_URL, tx_utils.DEFAULT_SPONSOR_FEE, address, None)
        params, err_response = get_json_params(logger, content, ["asset_fee"])
        if err_response:
            return err_response
        asset_fee, = params
        amount = asset_fee
        tx = tx_utils.sponsor_payload(address, pubkey, None, ASSET_ID, asset_fee, fee, timestamp)
    elif type_ == "setscript":
        fee = tx_utils.get_fee(NODE_BASE_URL, tx_utils.DEFAULT_SCRIPT_FEE, address, None)
        params, err_response = get_json_params(logger, content, ["script"])
        if err_response:
            return err_response
        script, = params
        tx = tx_utils.set_script_payload(address, pubkey, None, script, fee, timestamp)
    else:
        return bad_request("invalid type")

    txid = tx_utils.tx_to_txid(tx)
    dbtx = WavesTx.from_txid(db.session, txid)
    if dbtx:
        return bad_request("txid already exists")
    dbtx = WavesTx(txid, type, tx_utils.CTX_CREATED, amount, False, json.dumps(tx))
    db.session.add(dbtx)
    db.session.commit()
    return jsonify(dict(txid=txid, state=tx_utils.CTX_CREATED, tx=tx))

@app.route("/tx_status", methods=["POST"])
def tx_status():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["txid"])
    if err_response:
        return err_response
    txid, = params
    dbtx = WavesTx.from_txid(db.session, txid)
    if not dbtx:
        return bad_request('tx not found', 404)
    tx = dbtx.tx_with_sigs()
    return jsonify(dict(txid=txid, state=dbtx.state, tx=tx))

@app.route("/tx_serialize", methods=["POST"])
def tx_serialize():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["tx"])
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
    params, err_response = get_json_params(logger, content, ["txid", "signer_index", "signature"])
    if err_response:
        return err_response
    txid, signer_index, signature = params
    dbtx = WavesTx.from_txid(db.session, txid)
    if not dbtx:
        return bad_request('tx not found', 404)
    logger.info(":: adding sig to tx - {}, {}, {}".format(txid, signer_index, signature))
    sig = WavesTxSig(dbtx, signer_index, signature)
    db.session.add(sig)
    db.session.commit()
    tx = dbtx.tx_with_sigs()
    return jsonify(dict(txid=txid, state=dbtx.state, tx=tx))

@app.route("/tx_broadcast", methods=["POST"])
def tx_broadcast():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["txid"])
    if err_response:
        return err_response
    txid, = params
    dbtx = WavesTx.from_txid(db.session, txid)
    if not dbtx:
        return bad_request('tx not found', 404)
    tx = dbtx.tx_with_sigs()
    error = ""
    # broadcast transaction
    try:
        dbtx = tx_utils.broadcast_transaction(db.session, dbtx.txid)
        db.session.add(dbtx)
        db.session.commit()
    except OtherError as ex:
        error = ex.message
        if hasattr(ex, 'data'):
            error = "{} - {}".format(ex.message, ex.data)
    return jsonify(dict(txid=txid, state=dbtx.state, tx=tx, error=error))
