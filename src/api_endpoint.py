import logging
from datetime import datetime
import decimal

from flask import Blueprint, request, jsonify, flash, redirect, render_template, url_for
import flask_security
from flask_security.utils import hash_password, verify_password
from flask_security.recoverable import send_reset_password_instructions
import gevent

import web_utils
from web_utils import bad_request, get_json_params, auth_request, auth_request_get_single_param, auth_request_get_params
import utils
import email_utils
from models import BalanceUpdate, FiatDbTransaction, FiatDepositCode, Role, User, UserCreateRequest, UserUpdateEmailRequest, Permission, ApiKey, ApiKeyRequest, BrokerOrder, KycRequest, AddressBook, CryptoAddress, DassetSubaccount, WithdrawalConfirmation, UserInvitation, Remit, RemitConfirmation
from app_core import app, db, limiter, csrf, SERVER_VERSION, CLIENT_VERSION_DEPLOYED
from security import tf_enabled_check, tf_method, tf_code_send, tf_method_set, tf_method_unset, tf_secret_init, tf_code_validate, user_datastore
import windcave
import kyc_core
import dasset
import assets
from assets import MarketSide, market_side_is
import websocket
import fiatdb_core
import broker
import coordinator
import wallet
import tripwire
import tasks
import pouch_core
import depwith

logger = logging.getLogger(__name__)
api = Blueprint('api', __name__, template_folder='templates')
limiter.limit('100/minute')(api)
csrf.exempt(api)

# blueprint for supplemental routes of the api (like user confirmations etc), we separate this out so it have CSRF restrictions applied etc
api_supplemental = Blueprint('api_supplemental', __name__, template_folder='templates')
limiter.limit('100/minute')(api_supplemental)

def _user_subaccount_get_or_create(db_session, user):
    # create subaccount for user
    if not user.dasset_subaccount:
        subaccount_id = dasset.subaccount_create(user.token)
        if not subaccount_id:
            logger.error('failed to create subaccount for %s', user.email)
            return None
        subaccount = DassetSubaccount(user, subaccount_id)
        db_session.add(subaccount)
        return subaccount
    return user.dasset_subaccount

def _tf_check_withdrawal(user, tf_code):
    if tf_enabled_check(user):
        if not tf_code:
            return bad_request(web_utils.AUTH_FAILED)
        if not tf_code_validate(user, tf_code):
            return bad_request(web_utils.AUTH_FAILED)
    return None

def _redirect_confirmation_result(message, category):
    flash(message, category)
    return redirect('/apis/confirmation_result')

def _password_complexity_valid(password):
    if flask_security.utils.password_length_validator(password):
        logger.info('password length failed')
        return False
    if flask_security.utils.password_complexity_validator(password, True):
        logger.info('password complexity failed')
        return False
    if flask_security.utils.password_breached_validator(password):
        logger.info('password breached failed')
        return False
    return True

#
# Public API
#

@api.route('/version', methods=['GET', 'POST'])
def version():
    return jsonify(dict(server_version=SERVER_VERSION, client_version_deployed=CLIENT_VERSION_DEPLOYED))

@api_supplemental.route('/confirmation_result', methods=['GET'])
def confirmation_result():
    return render_template('api/confirmation_result.html')

#
# Private API
#

@api.route('/user_register', methods=['POST'])
@limiter.limit('20/minute')
def user_register():
    if not app.config['SECURITY_REGISTERABLE']:
        return bad_request(web_utils.NOT_AVAILABLE)
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["email", "password", "first_name", "last_name", "mobile_number", "address", "photo", "photo_type"])
    if err_response:
        return err_response
    email, password, first_name, last_name, mobile_number, address, photo, photo_type = params
    if not utils.is_email(email):
        return bad_request(web_utils.INVALID_EMAIL)
    email = email.lower()
    if not password:
        return bad_request(web_utils.EMPTY_PASSWORD)
    if not _password_complexity_valid(password):
        return bad_request(web_utils.WEAK_PASSWORD)
    if photo and len(photo) > 50000:
        return bad_request(web_utils.PHOTO_DATA_LARGE)
    req = UserCreateRequest(first_name, last_name, email, mobile_number, address, photo, photo_type, hash_password(password))
    user = User.from_email(db.session, email)
    if user:
        gevent.sleep(5)
        return bad_request(web_utils.USER_EXISTS)
    email_utils.email_user_create_request(req)
    db.session.add(req)
    db.session.commit()
    return 'ok'

def _user_create_confirmed(email: str, password: str, first_name: str | None, last_name: str | None, mobile_number: str | None, address: str | None, photo: str | None, photo_type: str | None) -> User:
    user = user_datastore.create_user(email=email, password=password, first_name=first_name, last_name=last_name)
    user.mobile_number = mobile_number
    user.address = address
    user.photo = photo
    user.photo_type = photo_type
    user.confirmed_at = datetime.now()
    return user

@api_supplemental.route('/user_registration_confirm/<token>', methods=['GET'])
@limiter.limit('20/minute')
def user_registration_confirm(token=None):
    if not token:
        return _redirect_confirmation_result('Invalid request', 'danger')
    if not app.config['SECURITY_REGISTERABLE']:
        return bad_request(web_utils.NOT_AVAILABLE)
    req = UserCreateRequest.from_token(db.session, token)
    if not req:
        return _redirect_confirmation_result('User registration request not found.', 'danger')
    user = User.from_email(db.session, req.email)
    if user:
        return _redirect_confirmation_result('User already exists.', 'danger')
    now = datetime.now()
    if now > req.expiry:
        return _redirect_confirmation_result('User registration expired.', 'danger')
    user = _user_create_confirmed(req.email, req.password, req.first_name, req.last_name, req.mobile_number, req.address, req.photo, req.photo_type)
    db.session.delete(req)
    db.session.commit()  # user added to session already
    return _redirect_confirmation_result('User registered.', 'success')

@api_supplemental.route('/invitation_confirm/<token>', methods=['GET', 'POST'])
@limiter.limit('20/minute')
def invitation_confirm(token=None):
    if not token:
        return _redirect_confirmation_result('Invalid request', 'danger')
    invite = UserInvitation.from_token(db.session, token)
    if not invite:
        return _redirect_confirmation_result('User invitation not found.', 'danger')
    user = User.from_email(db.session, invite.email)
    if user:
        return _redirect_confirmation_result('User already exists.', 'danger')
    now = datetime.now()
    if now > invite.expiry:
        return _redirect_confirmation_result('User invitation expired.', 'danger')
    if invite.claimed:
        return _redirect_confirmation_result('User invitation expired.', 'danger')
    if request.method == 'POST':
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        if not password:
            flash('Empty password', 'danger')
            return render_template('api/invitation_confirm.html', invite=invite)
        if not _password_complexity_valid(password):
            flash(web_utils.WEAK_PASSWORD, 'danger')
            return render_template('api/invitation_confirm.html', invite=invite)
        if password != password_confirm:
            flash('Passwords do not match', 'danger')
            return render_template('api/invitation_confirm.html', invite=invite)
        password = hash_password(password)
        user = _user_create_confirmed(invite.email, password=password, first_name=None, last_name=None, mobile_number=None, address=None, photo=None, photo_type=None)
        invite.claimed = True
        db.session.add(invite)
        db.session.commit()  # user added to session already
        return _redirect_confirmation_result('User registered.', 'success')
    return render_template('api/invitation_confirm.html', invite=invite)

@api.route('/user_two_factor_enabled_check', methods=['POST'])
@limiter.limit('10/hour')
def user_two_factor_enabled_check():
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["email", "password"])
    if err_response:
        return err_response
    email, password = params
    if not email:
        return bad_request(web_utils.INVALID_EMAIL)
    email = email.lower()
    user = User.from_email(db.session, email)
    if not user:
        gevent.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    if not verify_password(password, user.password):
        gevent.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    tf_code_send(user)
    return jsonify(dict(tf_enabled=tf_enabled_check(user)))

@api.route('/api_key_create', methods=['POST'])
@limiter.limit('20/minute')
def api_key_create():
    tripwire.login_attempt()
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["email", "password", "device_name", "tf_code"])
    if err_response:
        return err_response
    email, password, device_name, tf_code = params
    if not email:
        return bad_request(web_utils.INVALID_EMAIL)
    email = email.lower()
    user = User.from_email(db.session, email)
    if not user:
        gevent.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    if not verify_password(password, user.password):
        gevent.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    if tf_enabled_check(user) and not tf_code_validate(user, tf_code):
        return bad_request(web_utils.AUTH_FAILED)
    api_key = ApiKey(user, device_name)
    for name in Permission.PERMS_ALL:
        perm = Permission.from_name(db.session, name)
        assert perm
        api_key.permissions.append(perm)
    db.session.add(api_key)
    db.session.commit()
    return jsonify(dict(token=api_key.token, secret=api_key.secret, device_name=api_key.device_name, expiry=api_key.expiry))

@api.route('/api_key_request', methods=['POST'])
@limiter.limit('10/hour')
def api_key_request():
    tripwire.login_attempt()
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["email", "device_name"])
    if err_response:
        return err_response
    email, device_name = params
    if not email:
        return bad_request(web_utils.INVALID_EMAIL)
    email = email.lower()
    user = User.from_email(db.session, email)
    if not user:
        req = ApiKeyRequest(user, device_name)
        return jsonify(dict(token=req.token))
    req = ApiKeyRequest(user, device_name)
    email_utils.email_api_key_request(req)
    db.session.add(req)
    db.session.commit()
    tf_code_send(user)
    return jsonify(dict(token=req.token))

@api.route('/api_key_claim', methods=['POST'])
@limiter.limit('20/minute')
def api_key_claim():
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["token"])
    if err_response:
        return err_response
    token, = params
    req = ApiKeyRequest.from_token(db.session, token)
    if not req:
        gevent.sleep(5)
        return bad_request(web_utils.NOT_FOUND)
    if not req.created_api_key:
        gevent.sleep(5)
        return bad_request(web_utils.NOT_CREATED)
    api_key = req.created_api_key
    db.session.delete(req)
    db.session.commit()
    return jsonify(dict(token=api_key.token, secret=api_key.secret, device_name=api_key.device_name, expiry=api_key.expiry))

@api_supplemental.route('/api_key_confirm/<token>/<secret>', methods=['GET', 'POST'])
@limiter.limit('20/minute')
def api_key_confirm(token=None, secret=None):
    if not token or not secret:
        return _redirect_confirmation_result('Invalid request', 'danger')
    req = ApiKeyRequest.from_token(db.session, token)
    if not req:
        gevent.sleep(5)
        return _redirect_confirmation_result('Email login request not found.', 'danger')
    if req.secret != secret:
        return _redirect_confirmation_result('Email login code invalid.', 'danger')
    now = datetime.now()
    if now > req.expiry:
        gevent.sleep(5)
        return _redirect_confirmation_result('Email login request expired.', 'danger')
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        if not confirm:
            db.session.delete(req)
            db.session.commit()
            return _redirect_confirmation_result('Email login cancelled.', 'success')
        tf_code = request.form.get('tf_code')
        if tf_enabled_check(req.user) and (not tf_code or not tf_code_validate(req.user, tf_code)):
            return bad_request(web_utils.AUTH_FAILED)
        perms = request.form.getlist('perms')
        api_key = ApiKey(req.user, req.device_name)
        for name in perms:
            perm = Permission.from_name(db.session, name)
            if perm:
                api_key.permissions.append(perm)
        req.created_api_key = api_key
        db.session.add(req)
        db.session.add(api_key)
        db.session.commit()
        return _redirect_confirmation_result('Email login confirmed.', 'success')
    return render_template('api/api_key_confirm.html', req=req, perms=Permission.PERMS_ALL)

@api.route('/user_info', methods=['POST'])
def user_info():
    email, api_key, err_response = auth_request_get_single_param(db, "email")
    if err_response:
        return err_response
    assert api_key
    if not email:
        email = api_key.user.email
    else:
        email = email.lower()
    user = User.from_email(db.session, email)
    if not user:
        gevent.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    if user.email != api_key.user.email and not api_key.user.has_role(Role.ROLE_ADMIN):
        gevent.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    return jsonify(websocket.user_info_dict(api_key, email == api_key.user.email))

@api.route('/user_reset_password', methods=['POST'])
@limiter.limit('10/hour')
def user_reset_password():
    tripwire.login_attempt()
    api_key, err_response = auth_request(db)
    if err_response:
        return err_response
    assert api_key
    user = api_key.user
    send_reset_password_instructions(user)
    return 'ok'

@api.route('/user_update_email', methods=['POST'])
@limiter.limit('10/hour')
def user_update_email():
    tripwire.login_attempt()
    email, api_key, err_response = auth_request_get_single_param(db, "email")
    if err_response:
        return err_response
    assert api_key
    if not email:
        return bad_request(web_utils.INVALID_EMAIL)
    email = email.lower()
    user = User.from_email(db.session, email)
    if user:
        gevent.sleep(5)
        return bad_request(web_utils.USER_EXISTS)
    req = UserUpdateEmailRequest(api_key.user, email)
    email_utils.email_user_update_email_request(req)
    db.session.add(req)
    db.session.commit()
    tf_code_send(api_key.user)
    return 'ok'

@api_supplemental.route('/user_update_email_confirm/<token>', methods=['GET', 'POST'])
@limiter.limit('10/hour')
def user_update_email_confirm(token=None):
    if not token:
        return _redirect_confirmation_result('Invalid request', 'danger')
    req = UserUpdateEmailRequest.from_token(db.session, token)
    if not req:
        return _redirect_confirmation_result('User update email request not found.', 'danger')
    now = datetime.now()
    if now > req.expiry:
        return _redirect_confirmation_result('User update email request expired.', 'danger')
    user = User.from_email(db.session, req.email)
    if user:
        gevent.sleep(5)
        return bad_request(web_utils.USER_EXISTS)
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        if not confirm:
            db.session.delete(req)
            db.session.commit()
            return _redirect_confirmation_result('Email update cancelled.', 'success')
        tf_code = request.form.get('tf_code')
        if tf_enabled_check(req.user) and (not tf_code or not tf_code_validate(req.user, tf_code)):
            return bad_request(web_utils.AUTH_FAILED)
        user = req.user
        old_email = user.email
        user.email = req.email  # pyright: ignore [reportGeneralTypeIssues]  - I dont know!!!
        db.session.add(user)
        db.session.delete(req)
        db.session.commit()
        websocket.user_info_event(user, old_email)
        return _redirect_confirmation_result('User email updated.', 'success')
    return render_template('api/update_email_confirm.html', req=req)

@api.route('/user_update_password', methods=['POST'])
@limiter.limit('10/hour')
def user_update_password():
    params, api_key, err_response = auth_request_get_params(db, ["current_password", "new_password"])
    if err_response:
        return err_response
    assert params and api_key
    current_password, new_password = params
    user = api_key.user
    verified_password = verify_password(current_password, user.password)
    if not verified_password:
        return bad_request(web_utils.INCORRECT_PASSWORD)
    # set the new_password:
    if not _password_complexity_valid(new_password):
        return bad_request(web_utils.WEAK_PASSWORD)
    user.password = hash_password(new_password)
    db.session.add(user)
    db.session.commit()
    return 'password changed.'

@api.route('/user_kyc_request_create', methods=['POST'])
@limiter.limit('10/hour')
def user_kyc_request_create():
    api_key, err_response = auth_request(db)
    if err_response:
        return err_response
    assert api_key
    if list(api_key.user.kyc_requests):
        return bad_request(web_utils.KYC_REQUEST_EXISTS)
    user = api_key.user
    req = KycRequest(user)
    db.session.add(req)
    db.session.commit()
    websocket.user_info_event(user)
    return jsonify(dict(kyc_url=req.url(), aplyid_req_exists=req.aplyid is not None))

@api.route('/user_kyc_request_send_mobile_number', methods=['POST'])
@limiter.limit('10/hour')
def user_kyc_request_send_mobile_number():
    mobile_number, api_key, err_response = auth_request_get_single_param(db, "mobile_number")
    if err_response:
        return err_response
    assert mobile_number is not None and api_key
    if not list(api_key.user.kyc_requests):
        return bad_request(web_utils.KYC_REQUEST_NOT_EXISTS)
    req = api_key.user.kyc_requests[0]
    if not kyc_core.aplyid_request_init(req, mobile_number):
        return bad_request(web_utils.KYC_SEND_MOBILE_FAILED)
    db.session.commit()
    return jsonify(dict(kyc_url=req.url(), aplyid_req_exists=req.aplyid is not None))

@api.route('/user_update_photo', methods=['POST'])
@limiter.limit('10/hour')
def user_update_photo():
    params, api_key, err_response = auth_request_get_params(db, ["photo", "photo_type"])
    if err_response:
        return err_response
    assert params and api_key
    photo, photo_type = params
    user = api_key.user
    user.photo = photo
    user.photo_type = photo_type
    db.session.add(user)
    db.session.commit()
    websocket.user_info_event(user)
    return jsonify(dict(photo=user.photo, photo_type=user.photo_type))

@api.route('/user_two_factor_enable', methods=['POST'])
@limiter.limit('60/hour')
def user_two_factor_enable():
    code, api_key, err_response = auth_request_get_single_param(db, 'code')
    if err_response:
        return err_response
    assert api_key
    user = api_key.user
    if tf_enabled_check(user):
        return bad_request(web_utils.TWO_FACTOR_ENABLED)
    setup_values = None
    if not code:
        setup_values = tf_secret_init(user)
        if not tf_code_send(user):
            return bad_request(web_utils.FAILED_CODE_SEND)
    else:
        tf_method_set(user)
        if not tf_code_validate(user, code):
            return bad_request(web_utils.AUTH_FAILED)
    db.session.add(user)
    db.session.commit()
    websocket.user_info_event(user)
    return jsonify(dict(method=tf_method(), setup=setup_values))

@api.route('/user_two_factor_disable', methods=['POST'])
@limiter.limit('10/hour')
def user_two_factor_disable():
    code, api_key, err_response = auth_request_get_single_param(db, 'code')
    if err_response:
        return err_response
    assert api_key
    user = api_key.user
    if not tf_enabled_check(user):
        return bad_request(web_utils.TWO_FACTOR_DISABLED)
    if not code:
        if not tf_code_send(user):
            return bad_request(web_utils.FAILED_CODE_SEND)
    else:
        if not tf_code_validate(user, code):
            return bad_request(web_utils.AUTH_FAILED)
        tf_method_unset(user)
        db.session.add(user)
        db.session.commit()
        websocket.user_info_event(user)
    return jsonify(dict(method=tf_method(), setup=None))

@api.route('/user_two_factor_send', methods=['POST'])
@limiter.limit('60/hour')
def user_two_factor_send():
    api_key, err_response = auth_request(db)
    if err_response:
        return err_response
    assert api_key
    user = api_key.user
    if tf_enabled_check(user):
        if not tf_code_send(user):
            return bad_request(web_utils.FAILED_CODE_SEND)
    return jsonify(dict(method=tf_method(), setup=None))

@api.route('/assets', methods=['POST'])
def assets_req():
    _, err_response = auth_request(db)
    if err_response:
        return err_response
    return jsonify(assets=list(assets.ASSETS.values()))

@api.route('/markets', methods=['POST'])
def markets_req():
    _, err_response = auth_request(db)
    if err_response:
        return err_response
    return jsonify(markets=dasset.markets_data(use_cache=True))

@api.route('/order_book', methods=['POST'])
def order_book_req():
    market, _, err_response = auth_request_get_single_param(db, 'market')
    if err_response:
        return err_response
    if not market or market not in assets.MARKETS:
        return bad_request(web_utils.INVALID_MARKET)
    base_asset, quote_asset = assets.assets_from_market(market)
    base_asset_withdraw_fee = assets.asset_withdraw_fee(base_asset, None)
    quote_asset_withdraw_fee = assets.asset_withdraw_fee(quote_asset, None)
    order_book, broker_fee, broker_fee_fixed = dasset.order_book_data(market, use_cache=True)
    if not order_book:
        return bad_request(web_utils.FAILED_EXCHANGE)
    broker_fee_fixed_str = {}
    for key in broker_fee_fixed:
        broker_fee_fixed_str[key] = str(broker_fee_fixed[key])
    return jsonify(bids=order_book.bids, asks=order_book.asks, base_asset_withdraw_fee=str(base_asset_withdraw_fee), quote_asset_withdraw_fee=str(quote_asset_withdraw_fee), broker_fee=str(broker_fee), broker_fee_fixed=broker_fee_fixed_str)

@api.route('/balances', methods=['POST'])
def balances_req():
    api_key, err_response = auth_request(db)
    if err_response:
        return err_response
    assert api_key is not None
    balances = fiatdb_core.user_balances(db.session, api_key.user)
    balances_formatted = {}
    for asset, balance in balances.items():
        balance_dec = assets.asset_int_to_dec(asset, balance)
        balances_formatted[asset] = dict(symbol=asset, name=assets.ASSETS[asset].name, total=str(balance_dec), available=str(balance_dec))
    return jsonify(balances=balances_formatted)

def _validate_crypto_asset_deposit(asset: str, l2_network: str | None):
    if not assets.asset_is_crypto(asset):
        return bad_request(web_utils.INVALID_ASSET)
    if not assets.asset_has_l2(asset, l2_network):
        return bad_request(web_utils.INVALID_NETWORK)
    return None

@api_supplemental.route('/withdrawal_confirm/<token>/<secret>', methods=['GET', 'POST'])
@limiter.limit('20/minute')
def withdrawal_confirm(token=None, secret=None):
    if not token or not secret:
        return _redirect_confirmation_result('Invalid request.', 'danger')
    conf = WithdrawalConfirmation.from_token(db.session, token)
    if not conf or not conf.withdrawal:
        gevent.sleep(5)
        return _redirect_confirmation_result('Withdrawal confirmation not found.', 'danger')
    withdrawal: BalanceUpdate = conf.withdrawal
    if conf.secret != secret:
        return _redirect_confirmation_result('Withdrawal confirmation code invalid.', 'danger')
    if conf.confirmed is not None:
        return _redirect_confirmation_result('Withdrawal confirmation already processed.', 'danger')
    if conf.expired():
        gevent.sleep(5)
        return _redirect_confirmation_result('Withdrawal confirmation expired.', 'danger')
    if not conf.status_is_created():
        gevent.sleep(5)
        return _redirect_confirmation_result('Withdrawal invalid.', 'danger')
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        msg = ''
        with coordinator.lock:
            # check withdrawal status
            if withdrawal.status != withdrawal.STATUS_CREATED:
                return _redirect_confirmation_result('withdrawal status invalid', 'danger')
            # check withdrawal expiry
            if not assets.asset_recipient_expiry_valid(withdrawal.asset, withdrawal.l2_network, withdrawal.recipient):
                return _redirect_confirmation_result('withdrawal expired', 'danger')
            # update confirmation
            if confirm:
                conf.confirmed = True
                msg = 'Withdrawal confirmed.'
            else:
                conf.confirmed = False
                msg = 'Withdrawal cancelled.'
            db.session.add(conf)
            # commit changes
            db.session.commit()
            # update withdrawal asap
            tasks.task_manager.one_off('update withdrawal', tasks.update_withdrawal, [withdrawal.asset, withdrawal.token])
        return _redirect_confirmation_result(msg, 'success')
    asset = withdrawal.asset
    amount = withdrawal.amount
    amount_dec = assets.asset_int_to_dec(asset, amount)
    amount_str = assets.asset_dec_to_str(asset, amount_dec)
    formatted_amount = f'{amount_str} {asset}'
    return render_template('api/withdrawal_confirm.html', conf=conf, formatted_amount=formatted_amount)

@api.route('/crypto_deposit_recipient', methods=['POST'])
def crypto_deposit_recipient_req():
    params, api_key, err_response = auth_request_get_params(db, ['asset', 'l2_network', 'amount_dec'])
    if err_response:
        return err_response
    assert params and api_key
    asset, l2_network, amount_dec = params
    err_response = _validate_crypto_asset_deposit(asset, l2_network)
    if err_response:
        return err_response
    amount_dec = decimal.Decimal(amount_dec)

    # use local wallet if possible
    if wallet.deposits_supported(asset, l2_network):
        if not l2_network:
            crypto_address = CryptoAddress.from_asset(db.session, api_key.user, asset)
            if not crypto_address:
                address, err_msg = wallet.address_create(asset, l2_network)
                if not address:
                    return bad_request(web_utils.FAILED_WALLET)
                crypto_address = CryptoAddress(api_key.user, asset, address)
            crypto_address.viewed_at = int(datetime.timestamp(datetime.now()))
            crypto_address.check_interval = crypto_address.INITIAL_CHECK_INTERVAL  # type: ignore
            db.session.add(crypto_address)
            db.session.commit()
            return jsonify(recipient=crypto_address.address, asset=asset, l2_network=l2_network, amount_dec=decimal.Decimal(0))
        if amount_dec <= 0:
            return bad_request(web_utils.INVALID_AMOUNT)
        if not wallet.incoming_available(asset, l2_network, amount_dec):
            return bad_request(web_utils.INSUFFICIENT_LIQUIDITY)
        amount_int = assets.asset_dec_to_int(asset, amount_dec)
        crypto_deposit = BalanceUpdate.crypto_deposit(api_key.user, asset, l2_network, amount_int, 0, 'temp recipient')
        logger.info('create local wallet deposit: %s, %s, %s', asset, l2_network, amount_dec)
        wallet_reference, err_msg = wallet.deposit_create(asset, l2_network, crypto_deposit.token, 'deposit to Bitforge', amount_dec)
        if err_msg:
            return bad_request(f'{web_utils.FAILED_PAYMENT_CREATE} - {err_msg}')
        assert wallet_reference
        crypto_deposit.recipient = wallet_reference  # fill in real recipient here
        crypto_deposit.wallet_reference = wallet_reference
        db.session.add(crypto_deposit)
        db.session.commit()
        websocket.crypto_deposit_new_event(crypto_deposit)
        return jsonify(recipient=wallet_reference, asset=asset, l2_network=l2_network, amount_dec=amount_dec)

    # otherwise use dasset
    # get subaccount for user
    if not api_key.user.dasset_subaccount:
        logger.error('user %s dasset subaccount does not exist', api_key.user.email)
        return bad_request(web_utils.FAILED_EXCHANGE)
    subaccount = _user_subaccount_get_or_create(db.session, api_key.user)
    if not subaccount:
        return bad_request(web_utils.FAILED_EXCHANGE)
    db.session.commit()  # commit early so we only create subaccount once
    # create address
    crypto_address = CryptoAddress.from_asset(db.session, api_key.user, asset)
    if not crypto_address:
        address = dasset.address_get_or_create(asset, subaccount.subaccount_id)
        if not address:
            return bad_request(web_utils.FAILED_EXCHANGE)
        crypto_address = CryptoAddress(api_key.user, asset, address)
    crypto_address.viewed_at = int(datetime.timestamp(datetime.now()))
    crypto_address.check_interval = crypto_address.INITIAL_CHECK_INTERVAL  # type: ignore
    db.session.add(crypto_address)
    db.session.commit()
    return jsonify(recipient=crypto_address.address, asset=asset, l2_network=l2_network, amount_dec=decimal.Decimal(0))

def _validate_crypto_asset_withdraw(asset: str, l2_network: str | None, recipient: str | None):
    if not assets.asset_is_crypto(asset):
        return bad_request(web_utils.INVALID_ASSET)
    if not assets.asset_has_l2(asset, l2_network):
        return bad_request(web_utils.INVALID_NETWORK)
    if recipient and not assets.asset_recipient_validate(asset, l2_network, recipient):
        return bad_request(web_utils.INVALID_RECIPIENT)
    return None

@api.route('/crypto_withdrawal_create', methods=['POST'])
def crypto_withdrawal_create_req():
    params, api_key, err_response = auth_request_get_params(db, ['asset', 'l2_network', 'amount_dec', 'recipient', 'save_recipient', 'recipient_description', 'tf_code'])
    if err_response:
        return err_response
    assert params and api_key
    asset, l2_network, amount_dec, recipient, save_recipient, recipient_description, tf_code = params
    logger.info('crypto withdrawal: %s, %s, %s, %s', asset, l2_network, amount_dec, recipient)
    err_response = _tf_check_withdrawal(api_key.user, tf_code)
    if err_response:
        return err_response
    err_response = _validate_crypto_asset_withdraw(asset, l2_network, recipient)
    if err_response:
        return err_response
    amount_dec = decimal.Decimal(amount_dec)
    amount_from_recipient = assets.asset_recipient_extract_amount(asset, l2_network, recipient)
    if amount_dec == 0 and amount_from_recipient > 0:
        logger.info('amount from recipient: %s', amount_from_recipient)
        amount_dec = amount_from_recipient
    if amount_dec <= 0:
        return bad_request(web_utils.INVALID_AMOUNT)
    if amount_dec < assets.asset_min_withdraw(asset, l2_network):
        return bad_request(web_utils.AMOUNT_TOO_LOW)
    # check withdrawals enabled
    if not tripwire.WITHDRAWAL.ok:
        return bad_request(web_utils.NOT_AVAILABLE)
    tripwire.withdrawal_attempt()
    # save recipient
    if save_recipient and not l2_network:
        entry = AddressBook.from_recipient(db.session, api_key.user, asset, recipient)
        if entry:
            entry.description = recipient_description
        else:
            entry = AddressBook(api_key.user, asset, recipient, recipient_description, None, None, None, None)
        db.session.add(entry)
    # create withdrawal
    with coordinator.lock:
        crypto_withdrawal, err_response = depwith.crypto_withdrawal_create(db.session, api_key.user, asset, l2_network, amount_dec, recipient)
    if err_response:
        return err_response
    assert crypto_withdrawal
    # update user
    websocket.crypto_withdrawal_new_event(crypto_withdrawal)
    return jsonify(withdrawal=crypto_withdrawal.to_json())

@api.route('/fiat_deposit_windcave', methods=['POST'])
def fiat_deposit_windcave_req():
    params, api_key, err_response = auth_request_get_params(db, ['asset', 'amount_dec'])
    if err_response:
        return err_response
    assert params and api_key
    asset, amount_dec = params
    if not assets.asset_is_fiat(asset):
        return bad_request(web_utils.INVALID_ASSET)
    amount_dec = decimal.Decimal(amount_dec)
    if amount_dec <= 0:
        return bad_request(web_utils.INVALID_AMOUNT)
    amount_int = assets.asset_dec_to_int(asset, amount_dec)
    fiat_deposit = BalanceUpdate.fiat_deposit(api_key.user, asset, amount_int, 0, 'temp recipient')
    payment_request = windcave.payment_create(amount_int, fiat_deposit.expiry)
    if not payment_request:
        return bad_request(web_utils.FAILED_PAYMENT_CREATE)
    fiat_deposit.recipient = f'windcave session id: {payment_request.windcave_session_id}'  # fill in real recipient here
    fiat_deposit.windcave_payment_request = payment_request
    db.session.add(fiat_deposit)
    db.session.add(payment_request)
    db.session.commit()
    websocket.fiat_deposit_new_event(fiat_deposit)
    return jsonify(deposit=fiat_deposit.to_json())

@api.route('/fiat_deposit_direct', methods=['POST'])
def fiat_deposit_direct_req():
    api_key, err_response = auth_request(db)
    if err_response:
        return err_response
    assert api_key
    deposit_code = FiatDepositCode.from_autobuy_asset(db.session, api_key.user, None)
    if not deposit_code:
        deposit_code = FiatDepositCode(api_key.user, None)
        db.session.add(deposit_code)
        db.session.commit()
    crown_account_number = app.config['CROWN_ACCOUNT_NUMBER']
    crown_account_code = app.config['CROWN_ACCOUNT_CODE']
    return jsonify(deposit=dict(account_number=crown_account_number, reference=crown_account_code, code=deposit_code.token, autobuy_asset=None))

@api.route('/fiat_deposit_autobuy', methods=['POST'])
def fiat_deposit_autobuy_req():
    autobuy_asset, api_key, err_response = auth_request_get_single_param(db, 'autobuy_asset')
    if err_response:
        return err_response
    assert autobuy_asset is not None and api_key
    if not assets.asset_is_crypto(autobuy_asset):
        return bad_request(web_utils.INVALID_ASSET)

    deposit_code = FiatDepositCode.from_autobuy_asset(db.session, api_key.user, autobuy_asset)
    if not deposit_code:
        deposit_code = FiatDepositCode(api_key.user, autobuy_asset)
        db.session.add(deposit_code)
        db.session.commit()
    crown_account_number = app.config['CROWN_ACCOUNT_NUMBER']
    crown_account_code = app.config['CROWN_ACCOUNT_CODE']
    return jsonify(deposit=dict(account_number=crown_account_number, reference=crown_account_code, code=deposit_code.token, autobuy_asset=autobuy_asset))

@api.route('/fiat_withdrawal_create', methods=['POST'])
def fiat_withdrawal_create_req():
    params, api_key, err_response = auth_request_get_params(db, ['asset', 'amount_dec', 'recipient', 'recipient_description', 'account_name', 'account_addr_01', 'account_addr_02', 'account_addr_country', 'tf_code'])
    if err_response:
        return err_response
    assert params and api_key
    asset, amount_dec, recipient, recipient_description, account_name, account_addr_01, account_addr_02, account_addr_country, tf_code = params
    err_response = _tf_check_withdrawal(api_key.user, tf_code)
    if err_response:
        return err_response
    if not assets.asset_is_fiat(asset):
        return bad_request(web_utils.INVALID_ASSET)
    amount_dec = decimal.Decimal(amount_dec)
    if amount_dec <= 0:
        return bad_request(web_utils.INVALID_AMOUNT)
    if amount_dec < assets.asset_min_withdraw(asset, None):
        return bad_request(web_utils.AMOUNT_TOO_LOW)
    if not assets.asset_recipient_validate(asset, None, recipient):
        return bad_request(web_utils.INVALID_RECIPIENT)
    # check withdrawals enabled
    if not tripwire.WITHDRAWAL.ok:
        return bad_request(web_utils.NOT_AVAILABLE)
    tripwire.withdrawal_attempt()
    entry = AddressBook.from_recipient(db.session, api_key.user, asset, recipient)
    if entry:
        entry.description = recipient_description
        entry.account_name = account_name
        entry.account_addr_01 = account_addr_01
        entry.account_addr_02 = account_addr_02
        entry.account_addr_country = account_addr_country
    else:
        entry = AddressBook(api_key.user, asset, recipient, recipient_description, account_name, account_addr_01, account_addr_02, account_addr_country)
    db.session.add(entry)
    with coordinator.lock:
        fee_dec = assets.asset_withdraw_fee(asset, None, amount_dec)
        amount_plus_fee_dec = amount_dec + fee_dec
        balance = fiatdb_core.user_balance(db.session, asset, api_key.user)
        balance_dec = assets.asset_int_to_dec(asset, balance)
        if balance_dec < amount_plus_fee_dec:
            return bad_request(web_utils.INSUFFICIENT_BALANCE)
        # step 1) create FiatWithdrawal and ftx and commit so that users balance is updated
        amount_int = assets.asset_dec_to_int(asset, amount_dec)
        fee_int = assets.asset_dec_to_int(asset, fee_dec)
        fiat_withdrawal = BalanceUpdate.fiat_withdrawal(api_key.user, asset, amount_int, fee_int, recipient)
        amount_plus_fee_int = assets.asset_dec_to_int(asset, amount_plus_fee_dec)
        ftx = fiatdb_core.tx_create(api_key.user, FiatDbTransaction.ACTION_DEBIT, asset, amount_plus_fee_int, f'fiat withdrawal: {fiat_withdrawal.token}')
        fiat_withdrawal.balance_tx = ftx
        db.session.add(fiat_withdrawal)
        db.session.add(ftx)
        db.session.commit()
        # step 2) create / send withdrawal confimation
        conf = WithdrawalConfirmation(fiat_withdrawal.user, fiat_withdrawal, entry)
        email_utils.email_withdrawal_confirmation(conf)
        db.session.add(conf)
        db.session.commit()
    # update user
    websocket.fiat_withdrawal_new_event(fiat_withdrawal)
    return jsonify(withdrawal=fiat_withdrawal.to_json())

@api.route('/deposits', methods=['POST'])
def deposits_req():
    params, api_key, err_response = auth_request_get_params(db, ['asset', 'l2_network', 'offset', 'limit'])
    if err_response:
        return err_response
    assert params and api_key
    asset, l2_network, offset, limit = params
    if not isinstance(offset, int):
        return bad_request(web_utils.INVALID_PARAMETER)
    if not isinstance(limit, int):
        return bad_request(web_utils.INVALID_PARAMETER)
    if limit > 1000:
        return bad_request(web_utils.LIMIT_TOO_LARGE)
    if asset == '*ALL*':
        deposits = BalanceUpdate.of_type(db.session, api_key.user, BalanceUpdate.TYPE_DEPOSIT, offset, limit)
        deposits = [deposit.to_json() for deposit in deposits]
        total = BalanceUpdate.total_of_type(db.session, api_key.user, BalanceUpdate.TYPE_DEPOSIT)
    else:
        deposits = BalanceUpdate.of_asset(db.session, api_key.user, BalanceUpdate.TYPE_DEPOSIT, asset, l2_network, offset, limit)
        deposits = [deposit.to_json() for deposit in deposits]
        total = BalanceUpdate.total_of_asset(db.session, api_key.user, BalanceUpdate.TYPE_DEPOSIT, asset, l2_network)
    return jsonify(deposits=deposits, offset=offset, limit=limit, total=total)

@api.route('/withdrawals', methods=['POST'])
def withdrawals_req():
    params, api_key, err_response = auth_request_get_params(db, ['asset', 'l2_network', 'offset', 'limit'])
    if err_response:
        return err_response
    assert params and api_key
    asset, l2_network, offset, limit = params
    if not isinstance(offset, int):
        return bad_request(web_utils.INVALID_PARAMETER)
    if not isinstance(limit, int):
        return bad_request(web_utils.INVALID_PARAMETER)
    if limit > 1000:
        return bad_request(web_utils.LIMIT_TOO_LARGE)
    if asset == '*ALL*':
        withdrawals = BalanceUpdate.of_type(db.session, api_key.user, BalanceUpdate.TYPE_WITHDRAWAL, offset, limit)
        total = BalanceUpdate.total_of_type(db.session, api_key.user, BalanceUpdate.TYPE_WITHDRAWAL)
    else:
        withdrawals = BalanceUpdate.of_asset(db.session, api_key.user, BalanceUpdate.TYPE_WITHDRAWAL, asset, l2_network, offset, limit)
        total = BalanceUpdate.total_of_asset(db.session, api_key.user, BalanceUpdate.TYPE_WITHDRAWAL, asset, l2_network)
    withdrawals = [withdrawal.to_json() for withdrawal in withdrawals]
    return jsonify(withdrawals=withdrawals, offset=offset, limit=limit, total=total)

@api.route('/address_book', methods=['POST'])
def address_book_req():
    asset, api_key, err_response = auth_request_get_single_param(db, 'asset')
    if err_response:
        return err_response
    assert api_key
    if asset not in assets.ASSETS:
        return bad_request(web_utils.INVALID_ASSET)
    entries = AddressBook.of_asset(db.session, api_key.user, asset)
    entries = [entry.to_json() for entry in entries]
    return jsonify(entries=entries, asset=asset)

def _broker_order_validate(user: User, market: str, side: MarketSide, amount_dec: str, use_cache=False):
    err_msg, order = broker.order_validate(db.session, user, market, side, decimal.Decimal(amount_dec), use_cache)
    if err_msg:
        return bad_request(err_msg), order
    return None, order

@api.route('/broker_order_validate', methods=['POST'])
def broker_order_validate():
    params, api_key, err_response = auth_request_get_params(db, ["market", "side", "amount_dec"])
    if err_response:
        return err_response
    assert params and api_key
    market, side, amount_dec = params
    side = MarketSide.parse(side)
    if not side:
        return bad_request(web_utils.INVALID_SIDE)
    err_response, order = _broker_order_validate(api_key.user, market, side, amount_dec, use_cache=True)
    if err_response:
        return err_response
    assert order
    return jsonify(broker_order=order.to_json())

@api.route('/broker_order_create', methods=['POST'])
def broker_order_create():
    params, api_key, err_response = auth_request_get_params(db, ["market", "side", "amount_dec"])
    if err_response:
        return err_response
    assert params and api_key
    market, side, amount_dec = params
    if not api_key.user.kyc_validated() and not dasset._account_mock():
        return bad_request(web_utils.KYC_NOT_VALIDATED)
    side = MarketSide.parse(side)
    if not side:
        return bad_request(web_utils.INVALID_SIDE)
    err_response, order = _broker_order_validate(api_key.user, market, side, amount_dec, use_cache=False)
    if err_response:
        return err_response
    assert order
    db.session.add(order)
    db.session.commit()
    websocket.broker_order_new_event(order)
    return jsonify(broker_order=order.to_json())

@api.route('/broker_order_status', methods=['POST'])
def broker_order_status():
    token, api_key, err_response = auth_request_get_single_param(db, 'token')
    if err_response:
        return err_response
    assert token is not None and api_key
    broker_order = BrokerOrder.from_token(db.session, token)
    if not broker_order or broker_order.user != api_key.user:
        return bad_request(web_utils.NOT_FOUND)
    return jsonify(broker_order=broker_order.to_json())

@api.route('/broker_order_accept', methods=['POST'])
def broker_order_accept():
    token, api_key, err_response = auth_request_get_single_param(db, 'token')
    if err_response:
        return err_response
    assert token and api_key
    broker_order = BrokerOrder.from_token(db.session, token)
    if not broker_order or broker_order.user != api_key.user:
        return bad_request(web_utils.NOT_FOUND)
    with coordinator.lock:
        err_msg, ftx = broker.order_accept(db.session, broker_order)
        if err_msg:
            return bad_request(err_msg)
        db.session.add(broker_order)
        db.session.add(ftx)
        db.session.commit()
    websocket.broker_order_update_event(broker_order)
    tasks.task_manager.one_off('process broker order', tasks.process_broker_order, [broker_order.token])
    return jsonify(broker_order=broker_order.to_json())

@api.route('/broker_orders', methods=['POST'])
def broker_orders():
    params, api_key, err_response = auth_request_get_params(db, ["offset", "limit"])
    if err_response:
        return err_response
    assert params and api_key
    offset, limit = params
    if not isinstance(offset, int):
        return bad_request(web_utils.INVALID_PARAMETER)
    if not isinstance(limit, int):
        return bad_request(web_utils.INVALID_PARAMETER)
    if limit > 1000:
        return bad_request(web_utils.LIMIT_TOO_LARGE)
    orders = BrokerOrder.from_user(db.session, api_key.user, offset, limit)
    orders = [order.to_json() for order in orders]
    total = BrokerOrder.total_for_user(db.session, api_key.user)
    return jsonify(dict(broker_orders=orders, offset=offset, limit=limit, total=total))

@api.route('/remit_payment_methods', methods=['POST'])
def remit_payment_methods():
    api_key, err_response = auth_request(db)
    if err_response:
        return err_response
    assert api_key
    res = pouch_core.payment_methods(quiet=True)
    if res.err:
        return bad_request(res.err.message)
    return jsonify(dict(methods=res.methods))

@api.route('/remit_invoice_create', methods=['POST'])
def remit_invoice_create():
    params, api_key, err_response = auth_request_get_params(db, ["payment_method_category", "payment_method_code", "payment_method_name", "name", "account_number", "mobile_number", "currency", "amount", "description"])
    if err_response:
        return err_response
    assert params and api_key
    payment_method_category, payment_method_code, payment_method_name, name, account_number, mobile_number, currency, amount, description = params
    if not payment_method_code or not name or not currency or not description:
        return bad_request(web_utils.INVALID_PARAMETER)
    if not isinstance(amount, int):
        return bad_request(web_utils.INVALID_PARAMETER)
    if amount <= 0:
        return bad_request(web_utils.AMOUNT_TOO_LOW)
    # set pouch webhooks
    url = url_for('pouch.webhook', _external=True, _scheme='https')
    pouch_core.webhook_set(pouch_core.WEBHOOK_INVOICE_PAID, url, quiet=True)
    pouch_core.webhook_set(pouch_core.WEBHOOK_INVOICE_FAILED, url, quiet=True)
    # create invoice
    recipient = pouch_core.PouchRecipient(name, account_number, mobile_number)
    req = pouch_core.PouchInvoiceReq(description, payment_method_code, currency, amount, recipient)
    res = pouch_core.invoice_create(req, quiet=True)
    if res.err:
        return bad_request(res.err.message)
    assert res.invoice
    invoice = res.invoice
    # validate amount
    amount_extracted_dec = assets.asset_recipient_extract_amount(assets.BTC.symbol, assets.BTCLN.symbol, invoice.bolt11)
    amount_extracted_int = assets.asset_dec_to_int(assets.BTC.symbol, amount_extracted_dec)
    if amount_extracted_int != amount:
        return bad_request(web_utils.INVALID_AMOUNT)
    if amount_extracted_int <= 0:
        return bad_request(web_utils.INVALID_AMOUNT)
    if amount_extracted_dec < assets.asset_min_withdraw(assets.BTC.symbol, assets.BTCLN.symbol):
        return bad_request(web_utils.AMOUNT_TOO_LOW)
    # create remit
    user = api_key.user
    remit = Remit(user, pouch_core.PROVIDER, invoice.ref_id, payment_method_category, payment_method_code, payment_method_name, amount, invoice.bolt11, invoice.recipient.amount, invoice.recipient.currency)
    db.session.add(remit)
    db.session.commit()
    return jsonify(dict(remit=remit.to_json(), invoice=invoice.to_json()))

@api.route('/remit_invoice_status', methods=['POST'])
def remit_invoice_status():
    ref_id, api_key, err_response = auth_request_get_single_param(db, "ref_id")
    if err_response:
        return err_response
    assert ref_id and api_key
    remit = Remit.from_reference_id(db.session, ref_id)
    if not remit or remit.user != api_key.user:
        return bad_request(web_utils.NOT_FOUND)
    res = pouch_core.invoice_status(ref_id, quiet=True)
    if res.err:
        return bad_request(res.err.message)
    invoice = res.invoice
    assert invoice
    return jsonify(dict(remit=remit.to_json(), invoice=invoice.to_json()))

@api_supplemental.route('/remit_invoice_confirm/<token>/<secret>', methods=['GET', 'POST'])
@limiter.limit('20/minute')
def remit_invoice_confirm(token=None, secret=None):
    if not token or not secret:
        return _redirect_confirmation_result('Invalid request.', 'danger')
    conf = RemitConfirmation.from_token(db.session, token)
    if not conf or not conf.remit:
        gevent.sleep(5)
        return _redirect_confirmation_result('Remit confirmation not found.', 'danger')
    remit: Remit = conf.remit
    if conf.secret != secret:
        return _redirect_confirmation_result('Remit confirmation code invalid.', 'danger')
    if conf.confirmed is not None:
        return _redirect_confirmation_result('Remit confirmation already processed.', 'danger')
    if conf.expired():
        gevent.sleep(5)
        return _redirect_confirmation_result('Remit confirmation expired.', 'danger')
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        msg = ''
        with coordinator.lock:
            # check confirmed status
            if conf.confirmed is not None:
                return _redirect_confirmation_result('Remit status invalid', 'danger')
            # check invoice expiry
            if not assets.asset_recipient_expiry_valid(assets.BTC.symbol, assets.BTCLN.symbol, remit.bolt11):
                return _redirect_confirmation_result('withdrawal expired', 'danger')
            # update confirmation
            if confirm:
                conf.confirmed = True
                msg = 'Remit confirmed.'
            else:
                conf.confirmed = False
                msg = 'Remit cancelled.'
            db.session.add(conf)
            # commit changes
            db.session.commit()
            # update withdrawal asap
            tasks.task_manager.one_off('update remit', tasks.update_remit, [remit.token])
        return _redirect_confirmation_result(msg, 'success')
    from_formatted_amount = None
    if remit.order:
        assert assets.market_side_is(remit.order.side, assets.MarketSide.BID)
        amount_dec = assets.asset_int_to_dec(remit.order.quote_asset, remit.order.quote_amount)
        amount_str = assets.asset_dec_to_str(remit.order.quote_asset, amount_dec)
        from_formatted_amount = f'{amount_str} {remit.order.quote_asset}'
    amount_dec = assets.asset_int_to_dec(assets.BTC.symbol, remit.amount)
    amount_str = assets.asset_dec_to_str(assets.BTC.symbol, amount_dec)
    send_formatted_amount = f'{amount_str} {assets.BTC.symbol}'
    return render_template('api/remit_confirm.html', conf=conf, from_formatted_amount=from_formatted_amount, send_formatted_amount=send_formatted_amount)

@api.route('/remit_invoice_accept', methods=['POST'])
def remit_invoice_accept():
    params, api_key, err_response = auth_request_get_params(db, ["ref_id", "market", "side", "amount_dec", "tf_code"])
    if err_response:
        return err_response
    assert params and api_key
    ref_id, market, side, amount_dec, tf_code = params
    # get remit
    remit = Remit.from_reference_id(db.session, ref_id)
    if not remit or remit.user != api_key.user:
        return bad_request(web_utils.NOT_FOUND)
    # get pouch invoice
    res = pouch_core.invoice_status(ref_id, quiet=True)
    if res.err:
        return bad_request(res.err.message)
    assert res.invoice
    invoice = res.invoice
    # check tf code
    err_response = _tf_check_withdrawal(api_key.user, tf_code)
    if err_response:
        return err_response
    # check withdrawals enabled
    if not tripwire.WITHDRAWAL.ok:
        return bad_request(web_utils.NOT_AVAILABLE)
    tripwire.withdrawal_attempt()
    # check withdrawal ok
    err_response = _validate_crypto_asset_withdraw(assets.BTC.symbol, assets.BTCLN.symbol, invoice.bolt11)
    if err_response:
        return err_response
    amount_remit_dec = assets.asset_int_to_dec(assets.BTC.symbol, remit.amount)
    amount_extracted_dec = assets.asset_recipient_extract_amount(assets.BTC.symbol, assets.BTCLN.symbol, invoice.bolt11)
    if amount_remit_dec != amount_extracted_dec:
        return bad_request(web_utils.INVALID_AMOUNT)
    if amount_extracted_dec <= 0:
        return bad_request(web_utils.INVALID_AMOUNT)
    if amount_extracted_dec < assets.asset_min_withdraw(assets.BTC.symbol, assets.BTCLN.symbol):
        return bad_request(web_utils.AMOUNT_TOO_LOW)
    with coordinator.lock:
        # check status
        if remit.status != remit.STATUS_CREATED:
            return bad_request(web_utils.INVALID_STATUS)
        remit.status = remit.STATUS_SENDING
        db.session.add(remit)
        # get order info / create order
        if market:
            remit.status = remit.STATUS_EXCHANGING
            side = MarketSide.parse(side)
            if not side:
                return bad_request(web_utils.INVALID_SIDE)
            if not amount_dec:
                return bad_request(web_utils.INVALID_AMOUNT)
            # create order
            err_response, order = _broker_order_validate(api_key.user, market, side, amount_dec, use_cache=False)
            if err_response:
                return err_response
            assert order
            remit.order = order
            db.session.add(order)
            db.session.add(remit)
            db.session.commit()
            # accept order
            err_msg, ftx = broker.order_accept(db.session, order)
            if err_msg:
                return bad_request(err_msg)
            db.session.add(order)
            db.session.add(ftx)
            db.session.commit()
            websocket.broker_order_new_event(order)
            tasks.task_manager.one_off('process broker order', tasks.process_broker_order, [order.token])
    # update user
    conf = RemitConfirmation(remit.user, remit)
    email_utils.email_remit_confirmation(conf)
    db.session.add(conf)
    db.session.commit()
    return jsonify(remit=remit.to_json(), invoice=res.invoice.to_json())

@api.route('/remit_invoice_refund', methods=['POST'])
def remit_invoice_refund():
    ref_id, api_key, err_response = auth_request_get_single_param(db, "ref_id")
    if err_response:
        return err_response
    assert ref_id and api_key
    remit = Remit.from_reference_id(db.session, ref_id)
    if not remit or remit.user != api_key.user:
        return bad_request(web_utils.NOT_FOUND)
    withdrawal = remit.withdrawal
    if not withdrawal:
        return bad_request(web_utils.INVALID_STATUS)
    res = pouch_core.invoice_status(ref_id, quiet=True)
    if res.err:
        return bad_request(res.err.message)
    invoice = res.invoice
    assert invoice
    if invoice.status != pouch_core.PouchInvoiceStatus.failed:
        return bad_request(web_utils.INVALID_STATUS)
    # create BalanceUpdate deposit for user
    res = pouch_core.invoice_refund_deposit(remit)
    if res.err:
        return bad_request(res.err)
    crypto_deposit = res.deposit
    assert crypto_deposit
    db.session.add(crypto_deposit)
    db.session.commit()
    # make pouch refund
    assert crypto_deposit.wallet_reference
    res = pouch_core.invoice_refund(ref_id, crypto_deposit.wallet_reference, quiet=True)
    if res.err:
        return bad_request(res.err.message)
    invoice = res.invoice
    assert invoice
    return jsonify(dict(remit=remit.to_json(), invoice=invoice.to_json()))
