# pylint: disable=unbalanced-tuple-unpacking

import logging
import secrets
import os

from flask import Blueprint, render_template, request, flash, Markup, jsonify
from flask_security import roles_accepted
from bitcoin.rpc import Proxy

from utils import qrcode_svg_create
from web_utils import bad_request
from app_core import app, limiter
from models import Role
from ln import LnRpc, _msat_to_sat

logger = logging.getLogger(__name__)
ln_wallet = Blueprint('ln_wallet', __name__, template_folder='templates')
limiter.limit("100/minute")(ln_wallet)
BITCOIN_EXPLORER = app.config["BITCOIN_EXPLORER"]
TESTNET = app.config['TESTNET']

@ln_wallet.route('/')
@roles_accepted(Role.ROLE_ADMIN)
def ln_index():
    rpc = LnRpc()
    return render_template('lightning/index.html', funds_dict=rpc.list_funds())

@ln_wallet.route('/getinfo')
@roles_accepted(Role.ROLE_ADMIN)
def lightningd_getinfo():
    """ Returns template with info about lightningd"""
    rpc = LnRpc()
    return render_template('lightning/lightningd_getinfo.html', info=rpc.get_info())

@ln_wallet.route('/new_address', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def new_address_ep():
    """ Returns template showing a new address created by our HD wallet """
    address = None
    qrcode_svg = None
    if request.method == 'POST':
        address_type = request.form.get('address_type')
        rpc = LnRpc()
        address = rpc.new_address(address_type)
        qrcode_svg = qrcode_svg_create(address[address_type], 10)
    return render_template("lightning/new_address.html", address=address, qrcode_svg=qrcode_svg)

@ln_wallet.route('/list_txs')
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
        bitcoin_explorer=BITCOIN_EXPLORER)

@ln_wallet.route('/invoice', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def ln_invoice():
    """Create a lightning invoice"""
    label = None
    bolt11 = None
    qrcode_svg = None
    if request.method == 'POST':
        amount = request.form['amount']
        message = request.form['message']
        label = f"lbl-{secrets.token_urlsafe(8)}"
        rpc = LnRpc()
        bolt11 = rpc.invoice(int(amount), label, message)['bolt11']
        qrcode_svg = qrcode_svg_create(bolt11, 10)
    return render_template("lightning/invoice.html", bolt11=bolt11, label=label, qrcode_svg=qrcode_svg, funds_dict=LnRpc().list_funds())

@ln_wallet.route('/channel_management', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def channel_management():
    """ Returns a template listing all connected LN peers """
    rpc = LnRpc()
    if request.method == 'POST':
        form_name = request.form["form-name"]
        if form_name == 'rebalance_channel_form':
            oscid = request.form["oscid"]
            iscid = request.form["iscid"]
            sats = request.form["amount"]
            amount = str(int(sats))
            try:
                rpc = LnRpc()
                # pylint: disable=no-member
                # pylint: disable=unused-variable
                result = rpc.rebalance_channel(oscid, iscid, amount)
                flash(Markup(f'successfully move funds from: {oscid} to: {iscid} with the amount: {sats}sats'),'success')
            except Exception as e: # pylint: disable=broad-except
                flash(Markup(e.args[0]), 'danger')
        elif form_name == 'close_channel_form':
            peer_id = request.form["peer_id"]
            try:
                rpc = LnRpc()
                # pylint: disable=no-member
                # pylint: disable=unused-variable
                close_tx = rpc.close_channel(peer_id)
                flash(Markup(f'successfully close channel {peer_id}'), 'success')
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
                peers[i]["sats_total"] += _msat_to_sat(channel["msatoshi_total"])
                peers[i]["can_send"] += _msat_to_sat(channel["spendable_msatoshi"])
                peers[i]["can_receive"] += _msat_to_sat(channel["receivable_msatoshi"])
                for scid in channel["short_channel_id"]:
                    peers[i]["scid"] += scid
                peers[i]["channel_states"].append(channel["state"])
    return render_template("lightning/channel_management.html", peers=peers)

@ln_wallet.route('/list_forwards')
@roles_accepted(Role.ROLE_ADMIN)
def list_forwards():
    rpc = LnRpc()
    return rpc.list_forwards()

@ln_wallet.route('/pay_invoice', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def pay_invoice():
    """Returns template for paying LN invoices"""
    invoice = ''
    if request.method == 'POST':
        invoice = request.form['invoice']
        try:
            result = LnRpc().send_invoice(invoice)
            flash(f'Invoice paid: {result}', 'success')
        except Exception as e: # pylint: disable=broad-except
            flash(f'Error paying invoice: {e}', 'danger')
    return render_template("lightning/pay_invoice.html", invoice=invoice, funds_dict=LnRpc().list_funds())

@ln_wallet.route('/lightning_transactions', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def lightning_transactions():
    """ Returns received transactions """
    dict_txs = []
    unsorted_list_dict = []
    rpc = LnRpc()
    received_txs = rpc.list_invoices()
    send_txs = rpc.list_sendpays()
    funds_dict = rpc.list_funds()
    dict_txs.append(received_txs)
    dict_txs.append(send_txs)
    for unsorted_dict in dict_txs[0]:
        unsorted_list_dict.append(unsorted_dict)
    for unsorted_dict in dict_txs[1]:
        unsorted_list_dict.append(unsorted_dict)
    sorted_txs = sorted(unsorted_list_dict, key=lambda d: d["paid_at"], reverse=True)
    record_no = str(len(sorted_txs))
    return render_template("lightning/lightning_transactions.html", funds_dict=funds_dict, sorted_txs=sorted_txs, record_no=record_no)

@ln_wallet.route('/decode_bolt11/<bolt11>', strict_slashes=False)
@roles_accepted(Role.ROLE_ADMIN)
def decode_bolt11(bolt11=None):
    if not bolt11:
        return bad_request('please enter a non-empty bolt11 string')
    try:
        rpc = LnRpc()
        return rpc.decode_bolt11(str(bolt11))
    except Exception as e: # pylint: disable=broad-except
        return bad_request(str(e))

@ln_wallet.route('/channel_opener', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def channel_opener():
    if request.method == 'POST':
        amount = request.form["amount"]
        nodeid = request.form["nodeid"]
        try:
            rpc = LnRpc()
            rpc.connect_node(nodeid)
            node_id = nodeid.split("@")
            rpc.fund_channel(node_id[0], amount)
            flash(Markup(f'successfully added node id: {node_id[0]} with the amount: {amount}'), 'success')
        except Exception as e: # pylint: disable=broad-except
            flash(Markup(e.args[0]), 'danger')
    return render_template('lightning/channel_opener.html', funds_dict=LnRpc().list_funds())

@ln_wallet.route('/create_psbt', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def create_psbt():
    """ Returns template for creating a PSBT """
    rpc = LnRpc()
    onchain_sats = int(rpc.list_funds()["sats_onchain"])
    onchain = onchain_sats / 100000000
    addrs = []
    amounts = []
    mode = 'psbt'
    psbt = None
    if request.method == 'POST':
        addrs = request.form.getlist('address')
        amounts = request.form.getlist('amount')
        mode = request.form['mode']
        unit = request.form['unit']
        outputs = []
        for addr, amount in zip(addrs, amounts):
            outputs.append({addr: f'{amount}{unit}'})
        if mode == 'psbt':
            logger.info('preparing psbt with outputs: %s', outputs)
            try:
                res = rpc.prepare_psbt(outputs)
                psbt = res['psbt']
                flash('PSBT created', 'success')
            except Exception as e: # pylint: disable=broad-except
                flash(f'Failed to create PSBT: {e}', 'danger')
        elif mode == 'withdraw':
            logger.info('preparing withdrawal with outputs: %s', outputs)
            try:
                res = rpc.multi_withdraw(outputs)
                txid = res['txid']
                flash(f'Withdrawal transaction created: {txid}', 'success')
            except Exception as e: # pylint: disable=broad-except
                flash(f'Failed to create withdrawal transaction: {e}', 'danger')
        else:
            flash(f'Unknown mode: {mode}', 'danger')
    return render_template(
        'lightning/create_psbt.html', onchain=onchain, addrs=addrs, amounts=amounts, mode=mode, psbt=psbt, onchain_sats=onchain_sats)

@ln_wallet.route('/sign_psbt', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def sign_psbt():
    rpc = LnRpc()
    onchain_sats = int(rpc.list_funds()["sats_onchain"])
    onchain = onchain_sats / 100000000
    signed_psbt = None
    if request.method == 'POST':
        psbt = request.form["psbt"]
        try:
            rpc = LnRpc()
            res = rpc.sign_psbt(psbt)
            signed_psbt = res['signed_psbt']
            flash('Sign successful', 'success')
        except Exception as e: # pylint: disable=broad-except
            flash(f'Sign failed: {e}', 'danger')
    return render_template('lightning/sign_psbt.html', signed_psbt=signed_psbt, onchain=onchain, onchain_sats=onchain_sats)

@ln_wallet.route('/broadcast_psbt', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def broadcast():
    rpc = LnRpc()
    onchain_sats = int(rpc.list_funds()["sats_onchain"])
    onchain = onchain_sats / 100000000
    if request.method == 'POST':
        psbt = request.form["psbt"]
        try:
            rpc = LnRpc()
            res = rpc.send_psbt(psbt)
            txid = res['txid']
            flash(f'Broadcast successful, TXID: {txid}', 'success')
        except Exception as e: # pylint: disable=broad-except
            flash(f'Broadcast failed: {e}', 'danger')
    return render_template('lightning/broadcast_psbt.html', onchain=onchain, onchain_sats=onchain_sats)

def _build_bitcoin_rpc_url(bitcoin_datadir, bitcoin_host):
    btc_conf_file = os.path.join(bitcoin_datadir, 'bitcoin.conf')
    conf = {'rpcuser': ""}
    with open(btc_conf_file, 'r', encoding='utf-8') as fd:
        for line in fd.readlines():
            if '#' in line:
                line = line[:line.index('#')]
            if '=' not in line:
                continue
            k, v = line.split('=', 1)
            conf[k.strip()] = v.strip()
    authpair = f"{conf['rpcuser']}:{conf['rpcpassword']}"
    service_url = f"http://{authpair}@{bitcoin_host}:{conf['rpcport']}"
    return service_url

@ln_wallet.route('/decode_psbt')
@roles_accepted(Role.ROLE_ADMIN)
def decode_psbt():
    psbt = request.args['psbt']
    if not psbt:
        return bad_request('empty psbt string')
    try:
        service_url = _build_bitcoin_rpc_url(app.config['BITCOIN_DATADIR'], app.config['BITCOIN_RPCCONNECT'])
        connection = Proxy(service_url=service_url)
        psbt_json = connection._call('decodepsbt', psbt) # pylint: disable=protected-access
        logger.info('psbt json: %s', psbt_json)
        return jsonify(psbt_json)
    except Exception as e: # pylint: disable=broad-except
        return bad_request(str(e))
