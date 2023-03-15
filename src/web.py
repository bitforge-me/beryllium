#!/usr/bin/python3

from datetime import datetime, timedelta, date
import decimal
import logging
import math
import time

import gevent
from flask import redirect, render_template, request, flash, jsonify
from flask.wrappers import Response
from flask_security.decorators import roles_accepted

from app_core import app, boolify, db, socketio
from models import User, Role, Topic, PushNotificationLocation, BrokerOrder, BalanceUpdate, KycRequest, FiatDbTransaction, UserInvitation, CryptoAddress
import email_utils
from fcm import FCM
from web_utils import bad_request, get_json_params, get_json_params_optional
import broker
import depwith
from api_endpoint import api, api_supplemental
from reward_endpoint import reward
from reporting_endpoint import reporting
from payments_endpoint import payments
from kyc_endpoint import kyc
from ln_wallet_endpoint import ln_wallet
from monitor_endpoint import monitor
from support_endpoint import support
import websocket
import admin  # import to register flask admin endpoints
import dasset
import assets
import kyc_core
import fiatdb_core
import coordinator
import tripwire
import db_settings
import tasks
import utils
import httpreq
import wallet

USER_BALANCE_SHOW = 'show balance'
USER_BALANCE_CREDIT = 'credit'
USER_BALANCE_DEBIT = 'debit'
USER_BALANCE_SWEEP = 'sweep'

USER_WITHDRAWAL_SHOW = 'show'
USER_WITHDRAWAL_CANCEL = 'cancel'

WITHDRAWAL_TYPE_CRYPTO = 'crypto'
WITHDRAWAL_TYPE_FIAT = 'fiat'

USER_ORDER_SHOW = 'show'
USER_ORDER_CANCEL = 'cancel'

#jsonrpc = JSONRPC(app, "/api")
logger = logging.getLogger(__name__)
fcm = FCM(app.config["FIREBASE_CREDENTIALS"])

# blueprints
app.register_blueprint(api, url_prefix='/apiv1')
app.register_blueprint(api_supplemental, url_prefix='/apis')
app.register_blueprint(reward, url_prefix='/reward')
app.register_blueprint(reporting, url_prefix='/reporting')
app.register_blueprint(payments, url_prefix='/payments')
app.register_blueprint(kyc, url_prefix='/kyc')
app.register_blueprint(ln_wallet, url_prefix='/ln_wallet')
app.register_blueprint(monitor, url_prefix='/monitor')
app.register_blueprint(support, url_prefix='/support')

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
        except Exception as e:
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

@app.route('/send_email', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def send_email():
    recipient = ''
    subject = ''
    message = ''
    if request.method == 'POST':
        recipient = request.form['recipient']
        subject = request.form['subject']
        message = request.form['message']
        if not recipient:
            flash('Invalid recipient', 'danger')
            return render_template('send_email.html', recipient=recipient, subject=subject, message=message)
        if recipient == '*ALL*':
            users = User.all_active(db.session)
            for user in users:
                email_utils.send_email(subject, message, user.email)
            flash(f'Send email task created ({len(users)} users)', 'success')
        else:
            email_utils.send_email(subject, message, recipient)
            flash('Send email task created', 'success')
    return render_template('send_email.html', recipient=recipient, subject=subject, message=message)

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
            deposit = BalanceUpdate.from_token(db.session, recipient)
            if deposit:
                websocket.fiat_deposit_update_event(deposit)
                flash('Event sent', 'success')
            else:
                flash('Order not found', 'danger')
        elif event == 'crypto_deposit_update':
            deposit = BalanceUpdate.from_token(db.session, recipient)
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
                val = assets.asset_int_to_dec(key, val)
                balances[key] = assets.asset_dec_to_str(key, val)
            flash(str(balances), 'primary')
        elif action in (USER_BALANCE_CREDIT, USER_BALANCE_DEBIT):
            if asset not in asset_names:
                return return_response('Invalid asset')
            try:
                amount_dec = decimal.Decimal(amount)
            except Exception:
                amount_dec = decimal.Decimal(0)
            if amount_dec <= decimal.Decimal(0):
                return return_response('Invalid amount')
            amount_int = assets.asset_dec_to_int(asset, amount_dec)
            balance = fiatdb_core.user_balance(db.session, asset, user)
            balance = assets.asset_int_to_dec(asset, balance)
            balance = assets.asset_dec_to_str(asset, balance)
            flash(f'current balance: {balance} {asset}', 'primary')
            fiatdb_action = FiatDbTransaction.ACTION_CREDIT if action == USER_BALANCE_CREDIT else FiatDbTransaction.ACTION_DEBIT
            ftx = fiatdb_core.tx_create(user, fiatdb_action, asset, amount_int, desc)
            db.session.add(ftx)
            db.session.commit()
            balance = fiatdb_core.user_balance(db.session, asset, user)
            balance = assets.asset_int_to_dec(asset, balance)
            balance = assets.asset_dec_to_str(asset, balance)
            flash(f'new balance: {balance} {asset}', 'success')
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
                    flash(f'transfered {balance.available} of {balance.total} {balance.symbol} to master account', 'success')
                else:
                    flash(f'no available balance of {balance.total} {balance.symbol} to transfer', 'warning')
    return return_response()

@app.route('/user_withdrawal', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def user_withdrawal():
    actions = (USER_WITHDRAWAL_SHOW, USER_WITHDRAWAL_CANCEL)
    types = (WITHDRAWAL_TYPE_CRYPTO, WITHDRAWAL_TYPE_FIAT)
    action = type_ = token = ''

    def return_response(err_msg=None):
        if err_msg:
            flash(err_msg, 'danger')
        return render_template('user_withdrawal.html', actions=actions, types=types, type=type_, action=action, token=token)
    if request.method == 'POST':
        action = request.form['action']
        type_ = request.form['type']
        token = request.form['token']
        if action not in actions:
            return return_response('invalid action')
        if type_ not in types:
            return return_response('invalid type')
        if not token:
            return return_response('please enter a token')
        with coordinator.lock:
            if type_ == WITHDRAWAL_TYPE_CRYPTO:
                withdrawal = BalanceUpdate.from_token(db.session, token)
                if not withdrawal:
                    return return_response('Withdrawal not found')
                assert withdrawal.crypto and withdrawal.type == withdrawal.TYPE_WITHDRAWAL
            else:
                withdrawal = BalanceUpdate.from_token(db.session, token)
                if not withdrawal:
                    return return_response('Withdrawal not found')
                assert not withdrawal.crypto and withdrawal.type == withdrawal.TYPE_WITHDRAWAL
            if action == USER_WITHDRAWAL_SHOW:
                flash(str(withdrawal.to_json()), 'primary')
            elif action == USER_WITHDRAWAL_CANCEL:
                if withdrawal.status not in (withdrawal.STATUS_CREATED, withdrawal.STATUS_AUTHORIZED):
                    return return_response(f'invalid withdrawal status - {withdrawal.status}')
                ftx = depwith.withdrawal_cancel(withdrawal, 'admin')
                db.session.add(withdrawal)
                db.session.add(ftx)
                db.session.commit()
                flash(f'{type_} withdrawal {token} {action} completed', 'success')
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
        with coordinator.lock:
            order = BrokerOrder.from_token(db.session, token)
            if not order:
                return return_response('Order not found')
            if action == USER_ORDER_SHOW:
                flash(f'order: {order.to_json()}', 'primary')
            elif action == USER_ORDER_CANCEL:
                if order.status not in (order.STATUS_READY,):
                    return return_response('invalid order status')
                ftx = broker.order_refund(order)
                if not ftx:
                    return return_response('failed to create refund')
                order.status = order.STATUS_CANCELLED
                db.session.add(ftx)
                db.session.add(order)
                db.session.commit()
                flash(f'canceled and refunded order {token}', 'success')
    return return_response()

@app.route('/config', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def config():
    return render_template('config.html')

@app.route('/process_depwith_and_broker', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def process_depwith_broker():
    tasks.process_depwith_and_broker_orders()
    flash('processed deposits/withdrawals and orders', 'success')
    return redirect('/')

@app.route('/tripwire', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def tripwire_ep():
    return render_template('tripwire.html', data=tripwire.DATA)

@app.route('/db_test', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def db_test():
    return render_template('db_test.html')

def _db_test_read(delay_before: int, delay_after: int):
    time.sleep(delay_before)
    setting = db_settings.get('db_test')
    gevent.sleep(delay_after)
    if setting:
        return setting.value
    return ''

def _db_test_write(value: str):
    db_settings.set_value(db.session, 'db_test', value)
    db.session.commit()

@app.route('/db_test_action', methods=['POST'])
@roles_accepted(Role.ROLE_ADMIN)
def db_test_action():
    coordlock = boolify(request.form['coordlock'])
    action = request.form['action']
    if action == 'read':
        read_delay_before = int(request.form['read_delay_before'])
        read_delay_after = int(request.form['read_delay_after'])
        if coordlock:
            with coordinator.lock:
                return _db_test_read(read_delay_before, read_delay_after)
        return _db_test_read(read_delay_before, read_delay_after)
    elif action == 'write':
        value = request.form['value']
        if coordlock:
            with coordinator.lock:
                _db_test_write(value)
        else:
            _db_test_write(value)
        return 'ok'

@app.route('/task_test', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN)
def task_test():
    return render_template('task_test.html')

def _task_test(name: str, action: str, work_time: int, yield_after: int):
    assert action in ('cpu', 'http', 'postgres')
    logger.info('starting task: %s-%s for %dms (yield after %dms)', name, action, work_time, yield_after)
    finish_time = datetime.now() + timedelta(milliseconds=work_time)
    last_yield = datetime.now()
    while True:
        now = datetime.now()
        if finish_time < now:
            logger.info('finished task: %s-%s', name, action)
            return
        if action == 'cpu':
            if yield_after and now - timedelta(milliseconds=yield_after) > last_yield:
                logger.info('yielding task: %s-%s', name, action)
                last_yield = now
                utils.yield_gevent()
            # pointless calculation
            x = 999999999 * 999999999999999999999
        elif action == 'http':
            # pointless http request
            httpreq.get('https://google.com').text
        else:
            secs = work_time / 1000
            db.session.execute('select pg_sleep(:secs)', {'secs': secs})

@app.route('/task_test_action', methods=['POST'])
@roles_accepted(Role.ROLE_ADMIN)
def task_test_action():
    name = request.form['name']
    action = request.form['action']
    work_time = int(request.form['work_time'])
    assert work_time <= 10000
    yield_after = int(request.form['yield_after'])
    _task_test(name, action, work_time, yield_after)
    return 'ok'

@app.route('/bid_brute_force_test', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def bid_brute_force_test():
    if request.method == 'POST':
        market = request.form['market']
        quote_asset_amount = request.form['quote_asset_amount']
        quote_asset_amount = decimal.Decimal(quote_asset_amount)
        quote = dasset.bid_brute_force(market, quote_asset_amount, log=True)
        flash(str(quote))
    markets = assets.MARKETS.keys()
    return render_template('bid_brute_force_test.html', markets=markets)

@app.route('/unconfirmed_inputs_test', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def unconfirmed_inputs_test():
    minconf = 0
    addr = ''
    amount_sats = 50000
    if request.method == 'POST':
        minconf = int(request.form['minconf'])
        addr = request.form['addr']
        amount_sats = int(request.form['amount_sats'])
        txid, signed_psbt, err_msg = wallet.btc_signed_psbt_create([addr], [amount_sats], minconf=minconf)
        if err_msg:
            flash(err_msg, 'danger')
        else:
            flash(f'tx created: {txid}')
            assert txid
            if not wallet.btc_signed_psbt_discard(txid):
                flash(f'failed to discard tx: {txid}', 'danger')
    sats_available = wallet.btc_onchain_funds()
    sats_available_including_unconfirmed = wallet.btc_onchain_funds(included_unconfirmed=True)
    return render_template('unconfirmed_inputs_test.html', minconf=minconf, addr=addr, amount_sats=amount_sats, sats_available=sats_available, sats_available_including_unconfirmed=sats_available_including_unconfirmed)

@app.route('/invite_users', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def invite_users():
    addrs_raw = ''
    if request.method == 'POST':
        addrs_raw = request.form['addrs']
        if addrs_raw:
            addrs = addrs_raw.split('\n')
            addrs = [addr.strip().lower() for addr in addrs]
            for addr in addrs:
                if not addr:
                    continue
                if not utils.is_email(addr):
                    flash(f'invalid email ({addr})', 'danger')
                    return render_template('invite_users.html', addrs=addrs_raw)
                user = User.from_email(db.session, addr)
                if user:
                    flash(f'user exists ({addr})', 'danger')
                    return render_template('invite_users.html', addrs=addrs_raw)
            for addr in addrs:
                if not addr:
                    continue
                # invite addr to join
                invite = UserInvitation(addr)
                db.session.add(invite)
                db.session.commit()
                email_utils.email_invitation(invite)
            flash('invitations sent')
        else:
            flash('no emails', 'danger')
    return render_template('invite_users.html', addrs=addrs_raw)

@app.route('/check_addr', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def check_addr():
    email = ''
    asset = 'BTC'
    addr = ''
    new_crypto_deposits = []
    updated_crypto_deposits = []
    if request.method == 'POST':
        email = request.form['email']
        asset = request.form['asset']
        addr = request.form['addr']
        if not utils.is_email(email):
            flash(f'invalid email ({email})', 'danger')
            return render_template('check_addr.html', email=email, asset=asset, addr=addr)
        user = User.from_email(db.session, email)
        if not user:
            flash(f'user does not exist ({email})', 'danger')
            return render_template('check_addr.html', email=email, asset=asset, addr=addr)
        if not asset:
            flash(f'invalid asset ({asset})', 'danger')
            return render_template('check_addr.html', email=email, asset=asset, addr=addr)
        if not wallet.deposits_supported(asset, None):
            flash(f'invalid asset ({asset})', 'danger')
            return render_template('check_addr.html', email=email, asset=asset, addr=addr)
        addrs = []
        if not addr:
            db_addr = CryptoAddress.from_asset(db.session, user, asset)
            if not db_addr:
                flash(f'no addr found for user ({email})', 'danger')
                return render_template('check_addr.html', email=email, asset=asset, addr=addr)
            addrs.append(db_addr.address)
        else:
            addrs.append(addr)
        new_crypto_deposits, updated_crypto_deposits = depwith.crypto_addresses_check(db.session, user, asset, addrs)
        flash(f'checked address ({addrs[0]})')
    return render_template('check_addr.html', email=email, asset=asset, addr=addr, new_crypto_deposits=new_crypto_deposits, updated_crypto_deposits=updated_crypto_deposits)

@app.route('/reprocess_bank_deposits', methods=['GET', 'POST'])
@roles_accepted(Role.ROLE_ADMIN)
def reprocess_bank_deposits():
    def last_week_date():
        today = date.today()
        week = timedelta(days=7)
        last_week = today - week
        return last_week.strftime("%Y-%m-%d")

    def parse_date(date):
        return datetime.strptime(date, '%Y-%m-%d')

    INT_WEEK = '1w'
    INT_MONTH = '1m'
    start_date = last_week_date()
    interval = INT_WEEK
    new_fiat_deposits = []
    if request.method == 'POST':
        start_date = request.form['start_date']
        interval = request.form['interval']
        if not start_date:
            flash(f'invalid start date ({start_date})', 'danger')
            return render_template('reprocess_bank_deposits.html', start_date=start_date, interval=interval)
        if interval:
            interval = interval.lower()
        if interval not in (INT_WEEK, INT_MONTH):
            flash(f'invalid interval ({interval})', 'danger')
            return render_template('reprocess_bank_deposits.html', start_date=start_date, interval=interval)
        start_date_dt = parse_date(start_date)
        end_date_dt = start_date_dt + timedelta(days=7)
        if interval == INT_MONTH:
            end_date_dt = start_date_dt + timedelta(days=30)
        new_fiat_deposits = depwith.fiat_deposits_new_check(db.session, start_date_dt, end_date_dt)
        flash(f'checked deposits ({start_date}, {interval})')
    return render_template('reprocess_bank_deposits.html', start_date=start_date, interval=interval, new_fiat_deposits=new_fiat_deposits)

#
# gevent class
#

class WebGreenlet():

    def __init__(self, exception_func, addr="0.0.0.0", port=5000):
        self.addr = addr
        self.port = port
        # create greenlets
        self.runloop_greenlet = gevent.Greenlet(self._runloop)
        self.exception_func = exception_func
        if self.exception_func:
            self.runloop_greenlet.link_exception(self.exception_func)

    def _runloop(self):
        logger.info("WebGreenlet runloop started")
        logger.info("WebGreenlet webserver starting (addr: %s, port: %d)", self.addr, self.port)
        socketio.run(app, host=self.addr, port=self.port)

    def start(self):
        logger.info("starting WebGreenlet runloop...")
        # start greenlets
        self.runloop_greenlet.start()
        tasks.task_manager.start()

    def stop(self):
        self.runloop_greenlet.kill()
        greenlets = tasks.task_manager.kill()
        greenlets.append(self.runloop_greenlet)
        gevent.joinall(greenlets)

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
