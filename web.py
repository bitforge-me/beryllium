#!/usr/bin/python3

# pylint: disable=import-outside-toplevel
# pylint: disable=unbalanced-tuple-unpacking

import decimal
import logging
import math
import time

import gevent
from flask import render_template, request, flash, jsonify, Response
from flask_security import roles_accepted

from app_core import app, db, socketio
from models import User, Role, Topic, PushNotificationLocation, BrokerOrder, CryptoDeposit, FiatDeposit, KycRequest, FiatDbTransaction
import email_utils
from fcm import FCM
from web_utils import bad_request, get_json_params, get_json_params_optional
import broker
import depwith
from api_endpoint import api
from reward_endpoint import reward
from reporting_endpoint import reporting
from payments_endpoint import payments
from kyc_endpoint import kyc
import websocket
# pylint: disable=unused-import
import admin
import dasset
import assets
import kyc_core
import fiatdb_core
import coordinator
from ln import LnRpc

USER_BALANCE_SHOW = 'show balance'
USER_BALANCE_CREDIT = 'credit'
USER_BALANCE_DEBIT = 'debit'
USER_BALANCE_SWEEP = 'sweep'

USER_ORDER_SHOW = 'show'
USER_ORDER_CANCEL = 'cancel'

#jsonrpc = JSONRPC(app, "/api")
logger = logging.getLogger(__name__)
fcm = FCM(app.config["FIREBASE_CREDENTIALS"])

# blueprints
app.register_blueprint(api, url_prefix='/apiv1')
app.register_blueprint(reward, url_prefix='/reward')
app.register_blueprint(reporting, url_prefix='/reporting')
app.register_blueprint(payments, url_prefix='/payments')
app.register_blueprint(kyc, url_prefix='/kyc')

def process_email_alerts():
    with app.app_context():
        data = dasset.account_balances()
        for balance in data:
            if balance.symbol == 'NZD':
                if balance.available < app.config["MIN_AVAILABLE_NZD_BALANCE"]:
                    balance_format = assets.asset_dec_to_str(balance.symbol, balance.available)
                    subject = f"Available {balance.symbol} Balance below the minimum threshold"
                    msg = f"Available {balance.symbol} Balance needs to be replenished in the dasset account.<br/><br/>Available {balance.symbol} balance is: ${balance_format}"
                    email_utils.email_notification_alert(logger, subject, msg, app.config["ADMIN_EMAIL"])

def process_deposits_and_broker_orders():
    with app.app_context():
        logger.info('process deposits..')
        depwith.fiat_deposits_update(db.session)
        depwith.crypto_deposits_check(db.session)
        logger.info('process withdrawals..')
        depwith.fiat_withdrawals_update(db.session)
        depwith.crypto_withdrawals_update(db.session)
        logger.info('process broker orders..')
        broker.broker_orders_update(db.session)

#def qrcode_svg_create(data):
#    """ Returns SVG of input data """
#    factory = qrcode.image.svg.SvgPathImage
#    img = qrcode.make(data, image_factory=factory, box_size=35)
#    output = io.BytesIO()
#    img.save(output)
#    svg = output.getvalue().decode('utf-8')
#    return svg
#
#def qrcode_svg_create_ln(data):
#    """ Returns SVG of input data (LN focused) """
#    factory = qrcode.image.svg.SvgPathImage
#    img = qrcode.make(data, image_factory=factory, box_size=10)
#    output = io.BytesIO()
#    img.save(output)
#    svg = output.getvalue().decode('utf-8')
#    return svg

#
# Flask views
#

@app.route("/")
def index():
    return render_template("index.html")

# https://gis.stackexchange.com/a/2964
def meters_to_lat_lon_displacement(meters, origin_latitude):
    lat = meters / 111111
    lon = meters / (111111 * math.cos(math.radians(origin_latitude)))
    return lat, lon

@app.route("/push_notifications", methods=["GET", "POST"])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def push_notifications():
    type_ = ''
    topic = ''
    title = ''
    body = ''
    image = ''
    html = ''
    location = ''
    registration_token = ''
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        image = request.form["image"]
        html = request.form["html"]
        try:
            type_ = request.form["type"]
            if type_ == "topic":
                topic = request.form["topic"]
                fcm.send_to_topic(topic, title, body, image, html)
                flash(f"sent push notification ({topic})", "success")
            elif type_ == "location":
                location = request.form["location"]
                parts = location.split(',')
                if len(parts) != 4:
                    raise Exception('invalid location parameter')
                latitude, longitude, max_dist_meters, max_age_minutes = parts
                latitude = float(latitude)
                longitude = float(longitude)
                max_dist_meters = int(max_dist_meters)
                max_age_minutes = int(max_age_minutes)
                max_lat_delta, max_long_delta = meters_to_lat_lon_displacement(max_dist_meters, latitude)
                tokens = PushNotificationLocation.tokens_at_location(db.session, latitude, max_lat_delta, longitude, max_long_delta, max_age_minutes)
                tokens = [x.fcm_registration_token for x in tokens]
                fcm.send_to_tokens(tokens, title, body, image, html)
                count = len(tokens)
                flash(f"sent push notification ({count} devices)", "success")
            else:
                registration_token = request.form["registration_token"]
                fcm.send_to_tokens([registration_token], title, body, image, html)
                flash("sent push notification", "success")
        except Exception as e: # pylint: disable=broad-except
            flash(str(e.args[0]), "danger")
    topics = Topic.topic_list(db.session)
    return render_template("push_notifications.html", topics=topics, type_=type_, topic=topic, location=location, title=title, body=body, image=image, html=html, registration_token=registration_token)

@app.route("/push_notifications_register", methods=["POST"])
def push_notifications_register():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(content, ["registration_token"])
    if err_response:
        return err_response
    registration_token, = params
    latitude, longitude = get_json_params_optional(content, ["latitude", "longitude"])
    topics = Topic.topic_list(db.session)
    fcm.subscribe_to_topics(registration_token, topics)
    if latitude and longitude:
        latitude = float(latitude)
        longitude = float(longitude)
        push_location = PushNotificationLocation.from_token(db.session, registration_token)
        if push_location:
            push_location.update(latitude, longitude)
        else:
            push_location = PushNotificationLocation(registration_token, latitude, longitude)
        db.session.add(push_location)
        db.session.commit()
    return jsonify(dict(result="ok"))

@app.route('/test_email', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def test_email():
    recipient = ''
    subject = ''
    message = ''
    if request.method == 'POST':
        recipient = request.form['recipient']
        subject = request.form['subject']
        message = request.form['message']
        if email_utils.send_email(logger, subject, message, recipient):
            flash('Email sent', 'success')
        else:
            flash('Email failed', 'danger')
    return render_template('test_email.html', recipient=recipient, subject=subject, message=message)

@app.route('/test_ws', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def test_ws():
    recipient = ''
    event = ''
    events = ['user_info_update', 'broker_order_update', 'broker_order_new', 'fiat_deposit_update', 'fiat_deposit_new', 'crypto_deposit_update', 'crypto_deposit_new']
    if request.method == 'POST':
        recipient = request.form['recipient']
        event = request.form['event']
        if event == 'user_info_update':
            user = User.from_email(db.session, recipient)
            if user:
                websocket.user_info_event(user)
                flash('Event sent', 'success')
            else:
                flash('User not found', 'danger')
        elif event == 'broker_order_update':
            order = BrokerOrder.from_token(db.session, recipient)
            if order:
                websocket.broker_order_update_event(order)
                flash('Event sent', 'success')
            else:
                flash('Order not found', 'danger')
        elif event == 'fiat_deposit_update':
            deposit = FiatDeposit.from_token(db.session, recipient)
            if deposit:
                websocket.fiat_deposit_update_event(deposit)
                flash('Event sent', 'success')
            else:
                flash('Order not found', 'danger')
        elif event == 'crypto_deposit_update':
            deposit = CryptoDeposit.from_token(db.session, recipient)
            if deposit:
                websocket.crypto_deposit_update_event(deposit)
                flash('Event sent', 'success')
            else:
                flash('Order not found', 'danger')
        else:
            flash('Event not yet implemented', 'danger')
    return render_template('test_ws.html', recipient=recipient, event=event, events=events)

@app.route('/user_kyc', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def user_kyc():
    email = ''
    if request.method == 'POST':
        email = request.form['email']
        if not email:
            flash('please enter an email address', 'danger')
            return render_template('user_kyc.html')
        email = email.lower()
        user = User.from_email(db.session, email)
        if user:
            kycrequest = KycRequest.from_user(db.session, user)
            if not kycrequest:
                flash('User KYC not found', 'danger')
            elif kycrequest.status == kycrequest.STATUS_COMPLETED:
                token = kycrequest.token
                pdf = kyc_core.download_pdf_backup(token)
                if pdf:
                    return Response(
                        pdf,
                        mimetype="application/pdf",
                        headers={"Content-disposition":
                                 f"attachment; filename={email}.pdf"})
                flash('failed to download pdf', 'danger')
            elif kycrequest.status == kycrequest.STATUS_CREATED:
                flash('User KYC is created but not completed', 'danger')
        else:
            flash('User not found', 'danger')
    return render_template('user_kyc.html')

@app.route('/user_balance', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def user_balance():
    actions = (USER_BALANCE_SHOW, USER_BALANCE_CREDIT, USER_BALANCE_DEBIT, USER_BALANCE_SWEEP)
    asset_names = assets.ASSETS.keys()
    action = email = asset = amount = desc = ''
    def return_response(err_msg=None):
        if err_msg:
            flash(err_msg, 'danger')
        return render_template('user_balance.html', actions=actions, assets=asset_names, action=action, email=email, asset=asset, amount=amount, desc=desc)
    if request.method == 'POST':
        action = request.form['action']
        email = request.form['email']
        asset = request.form['asset']
        amount = request.form['amount']
        desc = request.form['desc']
        if action not in actions:
            return return_response('invalid action')
        if not email:
            return return_response('please enter an email address')
        email = email.lower()
        user = User.from_email(db.session, email)
        if not user:
            return return_response('User not found')
        if action == USER_BALANCE_SHOW:
            balances = fiatdb_core.user_balances(db.session, user)
            for key, val in balances.items():
                balances[key] = assets.asset_int_to_dec(key, val)
            flash(balances)
        elif action in (USER_BALANCE_CREDIT, USER_BALANCE_DEBIT):
            if asset not in asset_names:
                return return_response('Invalid asset')
            try:
                amount_dec = decimal.Decimal(amount)
            except: # pylint: disable=bare-except
                amount_dec = decimal.Decimal(0)
            if amount_dec <= decimal.Decimal(0):
                return return_response('Invalid amount')
            amount_int = assets.asset_dec_to_int(asset, amount_dec)
            balance = fiatdb_core.user_balance(db.session, asset, user)
            balance = assets.asset_int_to_dec(asset, balance)
            flash(f'current balance: {balance} {asset}')
            fiatdb_action = FiatDbTransaction.ACTION_CREDIT if action == USER_BALANCE_CREDIT else FiatDbTransaction.ACTION_DEBIT
            ftx = fiatdb_core.tx_create(db.session, user, fiatdb_action, asset, amount_int, desc)
            if not ftx:
                return return_response('failed to create transaction')
            db.session.add(ftx)
            db.session.commit()
            balance = fiatdb_core.user_balance(db.session, asset, user)
            balance = assets.asset_int_to_dec(asset, balance)
            flash(f'new balance: {balance} {asset}')
        elif action == USER_BALANCE_SWEEP:
            if not user.dasset_subaccount:
                return return_response('user does not have dasset subaccount')
            balances = dasset.account_balances(subaccount_id=user.dasset_subaccount.subaccount_id)
            if not balances:
                return return_response('failed to retreive dasset balances')
            for balance in balances:
                if balance.available > decimal.Decimal(0):
                    if not dasset.transfer(None, user.dasset_subaccount.subaccount_id, balance.symbol, balance.available):
                        return return_response(f'failed to transfer {balance.symbol} funds from {email} subaccount to master')
                    flash(f'transfered {balance.available} of {balance.total} {balance.symbol} to master account')
                else:
                    flash(f'no available balance of {balance.total} {balance.symbol} to transfer')
    return return_response()

@app.route('/user_order', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def user_order():
    actions = (USER_ORDER_SHOW, USER_ORDER_CANCEL)
    action = token = ''
    def return_response(err_msg=None):
        if err_msg:
            flash(err_msg, 'danger')
        return render_template('user_order.html', actions=actions, action=action, token=token)
    if request.method == 'POST':
        action = request.form['action']
        token = request.form['token']
        if action not in actions:
            return return_response('invalid action')
        if not token:
            return return_response('please enter a order token')
        order = BrokerOrder.from_token(db.session, token)
        if not order:
            return return_response('Order not found')
        if action == USER_ORDER_SHOW:
            flash(f'order: {order.to_json()}')
        elif action == USER_ORDER_CANCEL:
            if order.status not in (order.STATUS_READY,):
                return return_response('invalid order status')
            with coordinator.lock:
                side = assets.MarketSide.parse(order.side)
                ftx = broker.order_refund(db.session, order, side)
                if not ftx:
                    return return_response('failed to create refund')
                order.status = order.STATUS_CANCELLED
                db.session.add(ftx)
                db.session.add(order)
                db.session.commit()
            flash(f'canceled and refunded order {token}')
    return return_response()

@app.route('/ln', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def ln_ep():
    rpc = LnRpc()
    return render_template('ln.html', info=rpc.get_info(), funds_dict=rpc.list_funds())

@app.route('/ln/getinfo')
@roles_accepted(Role.ROLE_ADMIN)
def lightningd_getinfo_ep():
    rpc = LnRpc()
    """ Returns template with info about lightningd"""
    return render_template('lightning/lightningd_getinfo.html', info=rpc.get_info())

@app.route('/ln/send_bitcoin')
@roles_accepted(Role.ROLE_ADMIN)
def send_bitcoin():
    """ Returns template for sending BTC """
    rpc = LnRpc()
    onchain = int(rpc.list_funds()["sats_onchain"]) / 100000000
    return render_template(
        'lightning/send_bitcoin.html',
        bitcoin_explorer=app.config["BITCOIN_EXPLORER"],
        onchain=onchain)

@app.route('/ln/new_address')
@roles_accepted(Role.ROLE_ADMIN)
def new_address_ep():
    """ Returns template showing a new address created by our HD wallet """
    rpc = LnRpc()
    address = rpc.new_address()
    return render_template("lightning/new_address.html", address=address)

@app.route('/ln/list_txs')
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
        bitcoin_explorer=app.config["BITCOIN_EXPLORER"])

@app.route('/ln/ln_invoice', methods=['GET'])
def ln_invoice():
    """ Returns template for creating lightning invoices """
    return render_template("lightning/ln_invoice.html")

@app.route('/ln/create_invoice/<int:amount>/<string:message>/')
def create_invoice(amount, message):
    """ Returns template showing a created invoice from the inputs """
    rpc = LnRpc()
    bolt11 = rpc.create_invoice(int(amount * 1000), message)["bolt11"]
    qrcode_svg = qrcode_svg_create_ln(bolt11)
    return render_template(
        "lightning/create_invoice.html",
        bolt11=bolt11,
        qrcode_svg=qrcode_svg)

@app.route('/config', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def config():
    return render_template('config.html')

@roles_accepted(Role.ROLE_ADMIN)
@app.route('/ln/list_peers', methods=['GET', 'POST'])
def list_peers():
    """ Returns a template listing all connected LN peers """
    ln_instance = LnRpc()
    if request.method == 'POST':
        oscid = request.form["oscid"]
        iscid = request.form["iscid"]
        sats = request.form["amount"]
        amount = str(int(sats) * 1000) + str('msat')
        try:
            ln_instance = LnRpc()
            result = ln_instance.rebalance_individual_channel(
                oscid, iscid, amount)
            flash(
                Markup(f'successfully move funds from:'
                + '{oscid} to: {iscid} with the amount:'
                + '{sats}sats'),
                'success')
        except Exception as e:
            flash(Markup(e.args[0]), 'danger')
    peers = ln_instance.list_peers()["peers"]
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

@app.route('/ln/send_node')
def send_node():
    return render_template("lightning/send_node.html")

@app.route('/ln/list_forwards')
def list_forwards():
    ln_instance = LnRpc()
    return ln_instance.list_forwards()

'''
socket-io notifications
'''

@socketio.on('connect')
def test_connect(auth):
    print("Client connected")

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

@socketio.on('waitany')
def wait_any_invoice():
    print('client called recieveany')
    ln_instance = LnRpc()
    res = ln_instance.wait_any()
    emit('invoice', {'data': res})

#
# gevent class
#

class WebGreenlet():

    def __init__(self, exception_func, addr="0.0.0.0", port=5000):
        self.addr = addr
        self.port = port
        self.runloop_greenlet = None
        self.process_periodic_events_greenlet = None
        self.exception_func = exception_func

    def start(self):
        def runloop():
            logger.info("WebGreenlet runloop started")
            logger.info("WebGreenlet webserver starting (addr: %s, port: %d)", self.addr, self.port)
            socketio.run(app, host=self.addr, port=self.port)

        def process_periodic_events_loop():
            current = int(time.time())
            email_alerts_timer_last = current
            deposits_and_orders_timer_last = current
            while True:
                current = time.time()
                if current - email_alerts_timer_last > 1800:
                    gevent.spawn(process_email_alerts)
                    email_alerts_timer_last += 1800
                if current - deposits_and_orders_timer_last > 300:
                    gevent.spawn(process_deposits_and_broker_orders)
                    deposits_and_orders_timer_last += 300
                gevent.sleep(5)

        def start_greenlets():
            logger.info("starting WebGreenlet runloop...")
            self.runloop_greenlet.start()
            self.process_periodic_events_greenlet.start()

        # create greenlet
        self.runloop_greenlet = gevent.Greenlet(runloop)
        self.process_periodic_events_greenlet = gevent.Greenlet(process_periodic_events_loop)
        if self.exception_func:
            self.runloop_greenlet.link_exception(self.exception_func)
        # start greenlets
        gevent.spawn(start_greenlets)

    def stop(self):
        self.runloop_greenlet.kill()
        self.process_periodic_events_greenlet.kill()
        gevent.joinall([self.runloop_greenlet, self.process_periodic_events_greenlet])

def run():
    # setup logging
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(handler)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

    web_greenlet = WebGreenlet(None)
    web_greenlet.start()

    while 1:
        gevent.sleep(1)

    web_greenlet.stop()

if __name__ == "__main__":
    run()
