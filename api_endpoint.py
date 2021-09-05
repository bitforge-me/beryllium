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
from app_core import db, limiter
from models import user_datastore, User, UserCreateRequest, UserUpdateEmailRequest, Permission, ApiKey, ApiKeyRequest, BrokerOrder, KycRequest
import payments_core
import dasset
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

@api.route('/api_key_create', methods=['POST'])
@limiter.limit('10/hour')
def api_key_create():
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["email", "password", "device_name"])
    if err_response:
        return err_response
    email, password, device_name = params
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
    websocket.user_info_event(user)
    return 'ok'

@api.route('/user_update_email_confirm/<token>', methods=['GET'])
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
    user = req.user
    user.email = req.email
    db.session.add(user)
    db.session.delete(req)
    db.session.commit()
    websocket.user_info_event(user)
    flash('User email updated.', 'success')
    return redirect('/')

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
    return jsonify(dict(kyc_url=req.url()))

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
    symbol, _, err_response = auth_request_get_single_param(db, 'symbol')
    if err_response:
        return err_response
    if symbol not in dasset.MARKETS:
        return bad_request(web_utils.INVALID_MARKET)
    base_asset, quote_asset = dasset.assets_from_market(symbol)
    base_asset_withdraw_fee = dasset.asset_withdraw_fee(base_asset)
    quote_asset_withdraw_fee = dasset.asset_withdraw_fee(quote_asset)
    order_book, min_order, broker_fee = dasset.order_book_req(symbol)
    return jsonify(order_book=order_book, min_order=str(min_order), base_asset_withdraw_fee=str(base_asset_withdraw_fee), quote_asset_withdraw_fee=str(quote_asset_withdraw_fee), broker_fee=str(broker_fee))

@api.route('/broker_order_create', methods=['POST'])
def broker_order_create():
    params, api_key, err_response = auth_request_get_params(db, ["market", "side", "amount_dec", "recipient"])
    if err_response:
        return err_response
    market, side, amount_dec, recipient = params
    if not api_key.user.kyc_validated():
        return bad_request(web_utils.KYC_NOT_VALIDATED)
    if market not in dasset.MARKETS:
        return bad_request(web_utils.INVALID_MARKET)
    if side != dasset.MarketSide.BID.value:
        return bad_request(web_utils.INVALID_SIDE)
    side = dasset.MarketSide.BID
    amount_dec = decimal.Decimal(amount_dec)
    quote_amount_dec, err = dasset.bid_quote_amount(market, amount_dec)
    if err == dasset.QuoteResult.INSUFFICIENT_LIQUIDITY:
        return bad_request(web_utils.INSUFFICIENT_LIQUIDITY)
    if err == dasset.QuoteResult.AMOUNT_TOO_LOW:
        return bad_request(web_utils.AMOUNT_TOO_LOW)
    if not dasset.address_validate(market, side, recipient):
        return bad_request(web_utils.INVALID_RECIPIENT)
    base_asset, quote_asset = dasset.assets_from_market(market)
    amount = dasset.asset_dec_to_int(base_asset, amount_dec)
    quote_amount = dasset.asset_dec_to_int(quote_asset, quote_amount_dec)
    broker_order = BrokerOrder(api_key.user, market, side.value, amount, quote_amount, recipient)
    db.session.add(broker_order)
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
    req = payments_core.payment_create(broker_order.quote_amount, broker_order.expiry)
    if not req:
        return bad_request(web_utils.FAILED_PAYMENT_CREATE)
    broker_order.windcave_payment_request = req
    broker_order.status = broker_order.STATUS_READY
    db.session.add(req)
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
    if limit > 1000:
        return bad_request(web_utils.LIMIT_TOO_LARGE)
    orders = BrokerOrder.from_user(db.session, api_key.user, offset, limit)
    orders = [order.to_json() for order in orders]
    return jsonify(dict(broker_orders=orders))
