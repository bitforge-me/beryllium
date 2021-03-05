import logging
import time
import hmac
import hashlib
import base64
import datetime

from flask import Blueprint, request, jsonify, flash, redirect
import flask_security
from flask_security.utils import encrypt_password

from web_utils import bad_request, get_json_params
import utils
from app_core import app, db
from models import user_datastore, User, UserCreateRequest, ApiKey, Transaction
import paydb_core

logger = logging.getLogger(__name__)
paydb = Blueprint('paydb', __name__, template_folder='templates')

def to_bytes(data):
    if not isinstance(data, (bytes, bytearray)):
        return data.encode("utf-8")
    return data

def create_hmac_sig(api_secret, message):
    _hmac = hmac.new(to_bytes(api_secret), msg=to_bytes(message), digestmod=hashlib.sha256)
    signature = _hmac.digest()
    signature = base64.b64encode(signature).decode("utf-8")
    return signature

def check_hmac_auth(api_key, nonce, sig, body):
    if nonce <= api_key.nonce:
        return False, "old nonce"
    our_sig = create_hmac_sig(api_key.secret, body)
    if sig == our_sig:
        api_key.nonce = nonce
        return True, ""
    return False, "invalid signature"

def check_auth(api_key_token, nonce, sig, body):
    api_key = ApiKey.from_token(db.session, api_key_token)
    if not api_key:
        return False, "not found", None
    if not api_key.user.active:
        return False, "inactive account", None
    res, reason = check_hmac_auth(api_key, nonce, sig, body)
    if not res:
        return False, reason, None
    # update api key nonce
    db.session.commit()
    return True, "", api_key

@paydb.route('/user_register', methods=['POST'])
def user_register():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["email", "password", "first_name", "last_name", "photo"])
    if err_response:
        return err_response
    email, password, first_name, last_name, photo = params
    if not utils.is_email(email):
        return bad_request("invalid email address")
    if photo:
        photo = base64.b64decode(photo)
    else:
        photo = None
    req = UserCreateRequest(first_name, last_name, email, photo, encrypt_password(password))
    user = User.from_email(db.session, email)
    if user:
        time.sleep(5)
        return 'ok'
    utils.email_user_create_request(logger, req, req.MINUTES_EXPIRY)
    db.session.add(req)
    db.session.commit()
    return 'ok'

@paydb.route('/user_registration_confirm/<token>', methods=['GET'])
def user_registration_confirm(token=None):
    req = UserCreateRequest.from_token(db.session, token)
    if not req:
        flash('User registration request not found.', 'error')
        return redirect('/')
    user = User.from_email(db.session, req.email)
    if user:
        flash('User already exists.', 'error')
        return redirect('/')
    now = datetime.datetime.now()
    if now > req.expiry:
        flash('User registration expired.', 'error')
        return redirect('/')
    user = user_datastore.create_user(email=req.email, password=req.password, first_name=req.first_name, last_name=req.last_name)
    user.photo = req.photo
    user.confirmed_at = now
    db.session.delete(req)
    db.session.commit();
    flash('User registered.', 'success')
    return redirect('/')

@paydb.route('/api_key_create', methods=['POST'])
def api_key_create():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["email", "password", "device_name"])
    if err_response:
        return err_response
    email, password, device_name = params
    user = User.from_email(db.session, email)
    if not user:
        time.sleep(5)
        return bad_request('authentication failed')
    if not flask_security.verify_password(password, user.password):
        time.sleep(5)
        return bad_request('authentication failed')
    api_key = ApiKey(user, device_name)
    db.session.add(api_key)
    db.session.commit()
    return jsonify(dict(token=api_key.token, secret=api_key.secret, device_name=api_key.device_name, expiry=api_key.expiry))

@paydb.route('/user_info', methods=['POST'])
def user_info():
    sig = request.headers.get("X-Signature")
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["api_key", "nonce", "email"])
    if err_response:
        return err_response
    api_key, nonce, email = params
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    if not email:
        email = api_key.user.email
    user = User.from_email(db.session, email)
    if not user:
        time.sleep(5)
        return bad_request('authentication failed')
    if user == api_key.user:
        balance = paydb_core.user_balance(db.session, user)
        roles = [role.name for role in api_key.user.roles]
        # todo photo
        return jsonify(dict(email=user.email, balance=balance, photo='', roles=roles))
    # todo photo
    return jsonify(dict(email=user.email, balance=-1, photo='', roles=[]))

@paydb.route('/user_transactions', methods=['POST'])
def user_transactions():
    sig = request.headers.get("X-Signature")
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["api_key", "nonce", "offset", "limit"])
    if err_response:
        return err_response
    api_key, nonce, offset, limit = params
    if limit > 1000:
        return bad_request('limit too large (max 1000)')
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    txs = Transaction.related_to_user(db.session, api_key.user, offset, limit)
    txs = [tx.to_json() for tx in txs]
    return jsonify(dict(txs=txs))

@paydb.route('/transaction_create', methods=['POST'])
def transaction_create():
    sig = request.headers.get("X-Signature")
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["api_key", "nonce", "action", "recipient", "amount", "attachment"])
    if err_response:
        return err_response
    api_key, nonce, action, recipient, amount, attachment = params
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    tx, error = paydb_core.tx_create_and_play(db.session, api_key.user, action, recipient, amount, attachment)
    if not tx:
        return bad_request(error)
    return jsonify(dict(tx=tx.to_json()))

@paydb.route('/transaction_info', methods=['POST'])
def transaction_info():
    sig = request.headers.get("X-Signature")
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(logger, content, ["api_key", "nonce", "token"])
    if err_response:
        return err_response
    api_key, nonce, token = params
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    tx = Transaction.from_token(token)
    if not tx:
        return bad_request('invalid tx')
    if tx.user != api_key.user and tx.recipient != api_key.user:
        return bad_request('not authorized')
    return jsonify(dict(tx=tx.to_json()))