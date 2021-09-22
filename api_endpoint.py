# pylint: disable=unbalanced-tuple-unpacking

import logging
import time
import datetime
import decimal

from flask import Blueprint, request, jsonify, flash, redirect, render_template
import flask_security
from flask_security.utils import encrypt_password, verify_password
from flask_security.recoverable import send_reset_password_instructions

import web_utils
from web_utils import bad_request, get_json_params, auth_request, auth_request_get_single_param, auth_request_get_params
import utils
from models import DassetSubaccount, User, UserCreateRequest, UserUpdateEmailRequest, Permission, ApiKey, ApiKeyRequest, BrokerOrder, KycRequest, AddressBook
from app_core import db, limiter
from security import tf_enabled_check, tf_method, tf_code_send, tf_method_set, tf_method_unset, tf_secret_init, tf_code_validate, user_datastore
import payments_core
import kyc_core
import dasset
from dasset import MarketSide, market_side_is
import websocket

logger = logging.getLogger(__name__)
api = Blueprint('api', __name__, template_folder='templates')
limiter.limit('100/minute')(api)

#
# Private API
#

@api.route('/user_register', methods=['POST'])
@limiter.limit('10/hour')
def user_register():
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
    if photo and len(photo) > 50000:
        return bad_request(web_utils.PHOTO_DATA_LARGE)
    req = UserCreateRequest(first_name, last_name, email, mobile_number, address, photo, photo_type, encrypt_password(password))
    user = User.from_email(db.session, email)
    if user:
        time.sleep(5)
        return bad_request(web_utils.USER_EXISTS)
    utils.email_user_create_request(logger, req, req.MINUTES_EXPIRY)
    db.session.add(req)
    db.session.commit()
    return 'ok'

@api.route('/user_registration_confirm/<token>', methods=['GET'])
@limiter.limit('20/minute')
def user_registration_confirm(token=None):
    req = UserCreateRequest.from_token(db.session, token)
    if not req:
        flash('User registration request not found.', 'danger')
        return redirect('/')
    user = User.from_email(db.session, req.email)
    if user:
        flash('User already exists.', 'danger')
        return redirect('/')
    now = datetime.datetime.now()
    if now > req.expiry:
        flash('User registration expired.', 'danger')
        return redirect('/')
    user = user_datastore.create_user(email=req.email, password=req.password, first_name=req.first_name, last_name=req.last_name)
    user.mobile_number = req.mobile_number
    user.address = req.address
    user.photo = req.photo
    user.photo_type = req.photo_type
    user.confirmed_at = now
    db.session.delete(req)
    db.session.commit()
    flash('User registered.', 'success')
    return redirect('/')

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
        time.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    if not flask_security.verify_password(password, user.password):
        time.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    tf_code_send(user)
    return jsonify(dict(tf_enabled=tf_enabled_check(user)))

@api.route('/api_key_create', methods=['POST'])
@limiter.limit('10/hour')
def api_key_create():
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
        time.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    if not flask_security.verify_password(password, user.password):
        time.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    if tf_enabled_check(user) and not tf_code_validate(user, tf_code):
        return bad_request(web_utils.AUTH_FAILED)
    api_key = ApiKey(user, device_name)
    for name in Permission.PERMS_ALL:
        perm = Permission.from_name(db.session, name)
        api_key.permissions.append(perm)
    db.session.add(api_key)
    db.session.commit()
    return jsonify(dict(token=api_key.token, secret=api_key.secret, device_name=api_key.device_name, expiry=api_key.expiry))

@api.route('/api_key_request', methods=['POST'])
@limiter.limit('10/hour')
def api_key_request():
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
    utils.email_api_key_request(logger, req, req.MINUTES_EXPIRY)
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
    if not token:
        time.sleep(5)
        return bad_request(web_utils.NOT_FOUND)
    req = ApiKeyRequest.from_token(db.session, token)
    if not req.created_api_key:
        time.sleep(5)
        return bad_request(web_utils.NOT_CREATED)
    api_key = req.created_api_key
    db.session.delete(req)
    db.session.commit()
    return jsonify(dict(token=api_key.token, secret=api_key.secret, device_name=api_key.device_name, expiry=api_key.expiry))

@api.route('/api_key_confirm/<token>/<secret>', methods=['GET', 'POST'])
@limiter.limit('20/minute')
def api_key_confirm(token=None, secret=None):
    req = ApiKeyRequest.from_token(db.session, token)
    if not req:
        time.sleep(5)
        flash('Email login request not found.', 'danger')
        return redirect('/')
    if req.secret != secret:
        flash('Email login code invalid.', 'danger')
        return redirect('/')
    now = datetime.datetime.now()
    if now > req.expiry:
        time.sleep(5)
        flash('Email login request expired.', 'danger')
        return redirect('/')
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        if not confirm:
            db.session.delete(req)
            db.session.commit()
            flash('Email login cancelled.', 'success')
            return redirect('/')
        tf_code = request.form.get('tf_code')
        if tf_enabled_check(req.user) and not tf_code_validate(req.user, tf_code):
            return bad_request(web_utils.AUTH_FAILED)
        perms = request.form.getlist('perms')
        api_key = ApiKey(req.user, req.device_name)
        for name in perms:
            perm = Permission.from_name(db.session, name)
            api_key.permissions.append(perm)
        req.created_api_key = api_key
        db.session.add(req)
        db.session.add(api_key)
        db.session.commit()
        flash('Email login confirmed.', 'success')
        return redirect('/')
    return render_template('api/api_key_confirm.html', req=req, perms=Permission.PERMS_ALL)

@api.route('/user_info', methods=['POST'])
def user_info():
    email, api_key, err_response = auth_request_get_single_param(db, "email")
    if err_response:
        return err_response
    if not email:
        email = api_key.user.email
    else:
        email = email.lower()
    user = User.from_email(db.session, email)
    if not user:
        time.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    return jsonify(websocket.user_info_dict(api_key, user is api_key.user))

@api.route('/user_reset_password', methods=['POST'])
@limiter.limit('10/hour')
def user_reset_password():
    api_key, err_response = auth_request(db)
    if err_response:
        return err_response
    user = api_key.user
    send_reset_password_instructions(user)
    return 'ok'

@api.route('/user_update_email', methods=['POST'])
@limiter.limit('10/hour')
def user_update_email():
    email, api_key, err_response = auth_request_get_single_param(db, "email")
    if err_response:
        return err_response
    if not email:
        return bad_request(web_utils.INVALID_EMAIL)
    email = email.lower()
    user = User.from_email(db.session, email)
    if user:
        time.sleep(5)
        return bad_request(web_utils.USER_EXISTS)
    req = UserUpdateEmailRequest(api_key.user, email)
    utils.email_user_update_email_request(logger, req, req.MINUTES_EXPIRY)
    db.session.add(req)
    db.session.commit()
    tf_code_send(api_key.user)
    return 'ok'

@api.route('/user_update_email_confirm/<token>', methods=['GET', 'POST'])
@limiter.limit('10/hour')
def user_update_email_confirm(token=None):
    req = UserUpdateEmailRequest.from_token(db.session, token)
    if not req:
        flash('User update email request not found.', 'danger')
        return redirect('/')
    now = datetime.datetime.now()
    if now > req.expiry:
        flash('User update email request expired.', 'danger')
        return redirect('/')
    user = User.from_email(db.session, req.email)
    if user:
        time.sleep(5)
        return bad_request(web_utils.USER_EXISTS)
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        if not confirm:
            db.session.delete(req)
            db.session.commit()
            flash('Email update cancelled.', 'success')
            return redirect('/')
        tf_code = request.form.get('tf_code')
        if tf_enabled_check(req.user) and not tf_code_validate(req.user, tf_code):
            return bad_request(web_utils.AUTH_FAILED)
        user = req.user
        old_email = user.email
        user.email = req.email
        db.session.add(user)
        db.session.delete(req)
        db.session.commit()
        websocket.user_info_event(user, old_email)
        flash('User email updated.', 'success')
        return redirect('/')
    return render_template('api/update_email_confirm.html', req=req)

@api.route('/user_update_password', methods=['POST'])
@limiter.limit('10/hour')
def user_update_password():
    params, api_key, err_response = auth_request_get_params(db, ["current_password", "new_password"])
    if err_response:
        return err_response
    current_password, new_password = params
    user = api_key.user
    verified_password = verify_password(current_password, user.password)
    if not verified_password:
        return bad_request(web_utils.INCORRECT_PASSWORD)
    ### set the new_password:
    user.password = encrypt_password(new_password)
    db.session.add(user)
    db.session.commit()
    return 'password changed.'

@api.route('/user_kyc_request_create', methods=['POST'])
@limiter.limit('10/hour')
def user_kyc_request_create():
    api_key, err_response = auth_request(db)
    if err_response:
        return err_response
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
    photo, photo_type = params
    user = api_key.user
    user.photo = photo
    user.photo_type = photo_type
    db.session.add(user)
    db.session.commit()
    websocket.user_info_event(user)
    return jsonify(dict(photo=user.photo, photo_type=user.photo_type))

@api.route('/user_two_factor_enable', methods=['POST'])
@limiter.limit('10/hour')
def user_two_factor_enable():
    code, api_key, err_response = auth_request_get_single_param(db, 'code')
    if err_response:
        return err_response
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

@api.route('/assets', methods=['POST'])
def assets_req():
    _, err_response = auth_request(db)
    if err_response:
        return err_response
    return jsonify(assets=dasset.assets_req())

@api.route('/markets', methods=['POST'])
def markets_req():
    _, err_response = auth_request(db)
    if err_response:
        return err_response
    return jsonify(markets=dasset.markets_req())

@api.route('/order_book', methods=['POST'])
def order_book_req():
    market, _, err_response = auth_request_get_single_param(db, 'market')
    if err_response:
        return err_response
    if market not in dasset.MARKETS:
        return bad_request(web_utils.INVALID_MARKET)
    base_asset, quote_asset = dasset.assets_from_market(market)
    base_asset_withdraw_fee = dasset.asset_withdraw_fee(base_asset)
    quote_asset_withdraw_fee = dasset.asset_withdraw_fee(quote_asset)
    order_book, min_order, broker_fee = dasset.order_book_req(market)
    return jsonify(order_book=order_book, min_order=str(min_order), base_asset_withdraw_fee=str(base_asset_withdraw_fee), quote_asset_withdraw_fee=str(quote_asset_withdraw_fee), broker_fee=str(broker_fee))

@api.route('/address_book', methods=['POST'])
def address_book_req():
    asset, api_key, err_response = auth_request_get_single_param(db, 'asset')
    if err_response:
        return err_response
    if asset not in dasset.ASSETS:
        return bad_request(web_utils.INVALID_ASSET)
    entries = AddressBook.of_asset(db.session, api_key.user, asset)
    entries = [entry.to_json() for entry in entries]
    return jsonify(entries=entries, asset=asset)

@api.route('/broker_order_create', methods=['POST'])
def broker_order_create():
    params, api_key, err_response = auth_request_get_params(db, ["market", "side", "amount_dec", "recipient", "save_recipient", "recipient_description"])
    if err_response:
        return err_response
    market, side, amount_dec, recipient, save_recipient, recipient_description = params
    if not api_key.user.kyc_validated():
        return bad_request(web_utils.KYC_NOT_VALIDATED)
    if market not in dasset.MARKETS:
        return bad_request(web_utils.INVALID_MARKET)
    side = MarketSide.parse(side)
    if not side:
        return bad_request(web_utils.INVALID_SIDE)
    amount_dec = decimal.Decimal(amount_dec)
    if market_side_is(side, MarketSide.BID):
        quote_amount_dec, err = dasset.bid_quote_amount(market, amount_dec)
    else:
        quote_amount_dec, err = dasset.ask_quote_amount(market, amount_dec)
    if err == dasset.QuoteResult.INSUFFICIENT_LIQUIDITY:
        return bad_request(web_utils.INSUFFICIENT_LIQUIDITY)
    if err == dasset.QuoteResult.AMOUNT_TOO_LOW:
        return bad_request(web_utils.AMOUNT_TOO_LOW)
    if not dasset.recipent_validate(market, side, recipient):
        return bad_request(web_utils.INVALID_RECIPIENT)
    base_asset, quote_asset = dasset.assets_from_market(market)
    if not dasset.funds_available(quote_asset, quote_amount_dec):
        return bad_request(web_utils.INSUFFICIENT_LIQUIDITY)
    amount = dasset.asset_dec_to_int(base_asset, amount_dec)
    quote_amount = dasset.asset_dec_to_int(quote_asset, quote_amount_dec)
    broker_order = BrokerOrder(api_key.user, market, side.value, base_asset, quote_asset, amount, quote_amount, recipient)
    db.session.add(broker_order)
    if save_recipient:
        asset = base_asset
        if market_side_is(side, MarketSide.ASK):
            asset = quote_asset
        entry = AddressBook.from_recipient(db.session, api_key.user, asset, recipient)
        if entry:
            entry.description = recipient_description
        else:
            entry = AddressBook(api_key.user, asset, recipient, recipient_description)
        db.session.add(entry)
    db.session.commit()
    websocket.broker_order_new_event(broker_order)
    return jsonify(broker_order=broker_order.to_json())

@api.route('/broker_order_status', methods=['POST'])
def broker_order_status():
    token, api_key, err_response = auth_request_get_single_param(db, 'token')
    if err_response:
        return err_response
    broker_order = BrokerOrder.from_token(db.session, token)
    if not broker_order or broker_order.user != api_key.user:
        return bad_request(web_utils.NOT_FOUND)
    return jsonify(broker_order=broker_order.to_json())

@api.route('/broker_order_accept', methods=['POST'])
def broker_order_accept():
    token, api_key, err_response = auth_request_get_single_param(db, 'token')
    if err_response:
        return err_response
    broker_order = BrokerOrder.from_token(db.session, token)
    if not broker_order or broker_order.user != api_key.user:
        return bad_request(web_utils.NOT_FOUND)
    now = datetime.datetime.now()
    if now > broker_order.expiry:
        return bad_request(web_utils.EXPIRED)
    if broker_order.status != broker_order.STATUS_CREATED:
        return bad_request(web_utils.INVALID_STATUS)
    if market_side_is(broker_order.side, MarketSide.BID):
        # create nzd payment request
        req = payments_core.payment_create(broker_order.quote_amount, broker_order.expiry)
        if not req:
            return bad_request(web_utils.FAILED_PAYMENT_CREATE)
        broker_order.windcave_payment_request = req
        db.session.add(req)
    else:
        # create subaccount for user
        if not api_key.user.dasset_subaccount:
            subaccount_id = dasset.subaccount_create(api_key.user.token)
            if not subaccount_id:
                logger.error('failed to create subaccount for %s', api_key.user.email)
                return bad_request(web_utils.FAILED_EXCHANGE)
            subaccount = DassetSubaccount(api_key.user, subaccount_id)
            db.session.add(subaccount)
        else:
            subaccount_id = api_key.user.dasset_subaccount.subaccount_id
        # create crypto address
        address = dasset.address_get_or_create(broker_order.base_asset, subaccount_id)
        if not address:
            logger.error('failed to get address for %s (%s)', broker_order.base_asset, subaccount_id)
        broker_order.address = address
    # created payment request / crypto address now update the status and commit to db
    broker_order.status = broker_order.STATUS_READY
    db.session.add(broker_order)
    db.session.commit()
    websocket.broker_order_update_event(broker_order)
    return jsonify(broker_order=broker_order.to_json())

@api.route('/broker_orders', methods=['POST'])
def broker_orders():
    params, api_key, err_response = auth_request_get_params(db, ["offset", "limit"])
    if err_response:
        return err_response
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
