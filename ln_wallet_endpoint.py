# pylint: disable=unbalanced-tuple-unpacking

import logging
import time
import random

from flask import Blueprint, render_template, request, flash, Markup, url_for, redirect
from flask_security import roles_accepted

from utils import qrcode_svg_create
from app_core import app, limiter
from models import Role
from ln import LnRpc

logger = logging.getLogger(__name__)
ln_wallet = Blueprint('ln_wallet', __name__, template_folder='templates')
limiter.limit("100/minute")(ln_wallet)
bitcoin_explorer = app.config["BITCOIN_EXPLORER"]

@app.route('/')
@roles_accepted(Role.ROLE_ADMIN)
def index():
    rpc = LnRpc()
    return render_template('ln.html', funds_dict=rpc.list_funds())

@app.route('/getinfo')
@roles_accepted(Role.ROLE_ADMIN)
def lightningd_getinfo():
    """ Returns template with info about lightningd"""
    rpc = LnRpc()
    return render_template('lightning/lightningd_getinfo.html', info=rpc.get_info())

@app.route('/send_bitcoin')
@roles_accepted(Role.ROLE_ADMIN)
def send_bitcoin():
    """ Returns template for sending BTC """
    rpc = LnRpc()
    onchain = int(rpc.list_funds()["sats_onchain"]) / 100000000
    return render_template(
        'lightning/send_bitcoin.html',
        bitcoin_explorer=bitcoin_explorer,
        onchain=onchain)

@app.route('/new_address')
@roles_accepted(Role.ROLE_ADMIN)
def new_address_ep():
    """ Returns template showing a new address created by our HD wallet """
    rpc = LnRpc()
    address = rpc.new_address()
    return render_template("lightning/new_address.html", address=address)

@app.route('/list_txs')
@roles_accepted(Role.ROLE_ADMIN)
def list_txs():
    """ Returns template of on-chain txs """
    rpc = LnRpc()
    transactions = rpc.list_txs()
    sorted_txs = sorted(
        transactions["transactions"],
        key=lambda d: d["blockheight"],
        reverse=True)
    for tx in transactions["transactions"]:
        for output in tx["outputs"]:
            output["sats"] = int(output["msat"] / 1000)
            output.update({"sats": str(output["sats"]) + " satoshi"})
    return render_template(
        "lightning/list_transactions.html",
        transactions=sorted_txs,
        bitcoin_explorer=bitcoin_explorer)

@app.route('/ln_invoice', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def ln_invoice():
    """ Returns template for creating lightning invoices """
    return render_template("lightning/ln_invoice.html")

@app.route('/create_invoice/<int:amount>/<string:message>/')
@roles_accepted(Role.ROLE_ADMIN)
def create_invoice(amount, message):
    """ Returns template showing a created invoice from the inputs """
    rpc = LnRpc()
    bolt11 = rpc.invoice(int(amount * 1000), "lbl{}".format(random.random()), message)["bolt11"] # pylint: disable=consider-using-f-string
    qrcode_svg = qrcode_svg_create(bolt11, 10)
    return render_template(
        "lightning/create_invoice.html",
        bolt11=bolt11,
        qrcode_svg=qrcode_svg)

@app.route('/list_peers', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def list_peers():
    """ Returns a template listing all connected LN peers """
    rpc = LnRpc()
    if request.method == 'POST':
        oscid = request.form["oscid"]
        iscid = request.form["iscid"]
        sats = request.form["amount"]
        amount = str(int(sats) * 1000) + str('msat')
        try:
            rpc = LnRpc()
            # pylint: disable=no-member
            # pylint: disable=unused-variable
            result = rpc.rebalance_individual_channel(oscid, iscid, amount)
            flash(Markup(f'successfully move funds from: {oscid} to: {iscid} with the amount: {sats}sats'),'success')
        except Exception as e: # pylint: disable=broad-except
            flash(Markup(e.args[0]), 'danger')
    peers = rpc.list_peers()["peers"]
    # pylint: disable=consider-using-enumerate
    for i in range(len(peers)):
        peers[i]["sats_total"] = 0
        peers[i]["can_send"] = 0
        peers[i]["can_receive"] = 0
        peers[i]["scid"] = ""
        # I'm assuming there will only be one channel for each node, but I'm
        # using an array in case there's more
        peers[i]["channel_states"] = []
        for channel in peers[i]["channels"]:
            if channel["state"] == 'CHANNELD_NORMAL':
                peers[i]["sats_total"] += int(channel["msatoshi_total"]) / 1000
                peers[i]["can_send"] += int(channel["msatoshi_to_us"]) / 1000
                peers[i]["can_receive"] += int(
                    channel["out_msatoshi_fulfilled"]) / 1000
                for scid in channel["short_channel_id"]:
                    peers[i]["scid"] += scid
                peers[i]["channel_states"].append(channel["state"])

        # round as a last step, for accuracy
        peers[i]["sats_total"] = int(peers[i]["sats_total"])
        peers[i]["can_send"] = int(peers[i]["can_send"])
        peers[i]["can_receive"] = int(peers[i]["can_receive"])
    return render_template("lightning/list_peers.html", peers=peers)

@app.route('/send_node')
@roles_accepted(Role.ROLE_ADMIN)
def send_node():
    return render_template("lightning/send_node.html")

@app.route('/list_forwards')
@roles_accepted(Role.ROLE_ADMIN)
def list_forwards():
    rpc = LnRpc()
    return rpc.list_forwards()

@app.route('/withdraw', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def withdraw():
    rpc = LnRpc()
    outputs_dict = request.json["address_amount"]
    try:
        tx_result = rpc.multi_withdraw(outputs_dict)
    except BaseException: # pylint: disable=broad-except
        tx_result = "error"
    return tx_result

@app.route('/pay_invoice', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def pay_invoice():
    """ Returns template for paying LN invoices """
    return render_template("lightning/pay_invoice.html")

@app.route('/pay/<string:bolt11>')
@roles_accepted(Role.ROLE_ADMIN)
def ln_pay(bolt11):
    """ Returns template showing a paid LN invoice """
    rpc = LnRpc()
    try:
        invoice_result = rpc.send_invoice(bolt11)
        return render_template("lightning/pay.html", invoice_result=invoice_result)
    except BaseException: # pylint: disable=broad-except
        return redirect(url_for("pay_error"))

@app.route('/pay_error')
@roles_accepted(Role.ROLE_ADMIN)
def pay_error():
    """ Returns template for a generic pay error """
    return render_template("lightning/pay_error.html")


@app.route('/invoices', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def invoices():
    """ Returns template listing all LN paid invoices """
    rpc = LnRpc()
    paid_invoices = rpc.list_paid()
    return render_template("lightning/invoices.html", paid_invoices=paid_invoices)

@app.route('/decode_pay/<bolt11>', strict_slashes=False)
@roles_accepted(Role.ROLE_ADMIN)
def decode_pay(bolt11=None):
    if bolt11 is None:
        return "Please enter a non-empty bolt11 string"
    try:
        rpc = LnRpc()
        return rpc.decode_pay(str(bolt11))
    except Exception as e: # pylint: disable=broad-except
        return str(e)
    return "Something went wrong"


@app.route('/channel_opener', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def channel_opener():
    """ Returns template for opening LN channels """
    return render_template("lightning/channel_opener.html")

@app.route('/open_channel/<string:node_pubkey>/<int:amount>', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def open_channel(node_pubkey, amount):
    """ Opens a LN channel """
    rpc = LnRpc()
    try:
        rpc.connect_node(node_pubkey)
        node_id = node_pubkey.split("@")
        # pylint: disable=unused-variable
        result = rpc.fund_channel(node_id[0], amount)
        flash(Markup(f'successfully added node id: {node_id[0]} with the amount: {amount}'), 'success')
    except Exception as e: # pylint: disable=broad-except
        flash(Markup(e.args[0]), 'danger')
    return render_template("lightning/channel_opener.html")

@app.route('/create_psbt')
@roles_accepted(Role.ROLE_ADMIN)
def create_psbt():
    """ Returns template for creating a PSBT """
    rpc = LnRpc()
    onchain = int(rpc.list_funds()["sats_onchain"]) / 100000000
    return render_template(
        'lightning/create_psbt.html',
        bitcoin_explorer=bitcoin_explorer,
        onchain=onchain)

@app.route('/psbt', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def psbt():
    rpc = LnRpc()
    outputs_dict = request.json["address_amount"]
    try:
        tx_result = rpc.prepare_psbt(outputs_dict)
    except Exception as e: # pylint: disable=broad-except
        tx_result = str(e)
    return tx_result

@app.route('/send_psbt', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def send_psbt():
    rpc = LnRpc()
    outputs_dict = request.json["signed_psbt"]
    try:
        tx_result = rpc.send_psbt(outputs_dict)
    except Exception as e: # pylint: disable=broad-except
        tx_result = str(e)
    return tx_result

@app.route('/sign')
@roles_accepted(Role.ROLE_ADMIN)
def sign():
    return render_template('lightning/sign.html', bitcoin_explorer=bitcoin_explorer)

@app.route('/sign_psbt', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def sign_psbt():
    rpc = LnRpc()
    outputs_dict = request.json["unsigned_psbt"]
    try:
        tx_result = rpc.sign_psbt(outputs_dict)
    except Exception as e: # pylint: disable=broad-except
        tx_result = str(e)
    return tx_result

@app.route('/broadcast')
@roles_accepted(Role.ROLE_ADMIN)
def broadcast():
    return render_template('lightning/broadcast.html', bitcoin_explorer=bitcoin_explorer)
