# pylint: disable=unbalanced-tuple-unpacking

import logging
import time
import datetime
import json

from flask import Blueprint, request, jsonify, flash, redirect, render_template
import flask_security
from flask_security.utils import encrypt_password
from flask_socketio import Namespace, emit, join_room, leave_room

import web_utils
from web_utils import bad_request, get_json_params, request_get_signature, check_auth
import utils
from app_core import db, socketio
from models import user_datastore, User, UserCreateRequest, Permission, ApiKey, ApiKeyRequest, PayDbTransaction
import paydb_core

logger = logging.getLogger(__name__)
paydb = Blueprint('paydb', __name__, template_folder='templates')
ws_sids = {}

#
# Websocket events
#

NS = '/paydb'

def tx_event(txn):
    txt = json.dumps(txn.to_json())
    socketio.emit("tx", txt, json=True, room=txn.sender.email, namespace=NS)
    if txn.recipient and txn.recipient != txn.sender:
        socketio.emit("tx", txt, json=True, room=txn.recipient.email, namespace=NS)

class PayDbNamespace(Namespace):

    def on_error(self, err):
        logger.error(err)

    def on_connect(self):
        logger.info("connect sid: %s", request.sid)

    def on_auth(self, auth):
        # check auth
        res, reason, api_key = check_auth(db.session, auth["api_key"], auth["nonce"], auth["signature"], str(auth["nonce"]))
        if res:
            emit("info", "authenticated!", namespace=NS)
            # join room and store user
            logger.info("join room for email: %s", api_key.user.email)
            join_room(api_key.user.email)
            # store sid -> email map
            ws_sids[request.sid] = api_key.user.email
        else:
            logger.info("failed authentication (%s): %s", auth["api_key"], reason)

    def on_disconnect(self):
        logger.info("disconnect sid: %s", request.sid)
        if request.sid in ws_sids:
            # remove sid -> email map
            email = ws_sids[request.sid]
            logger.info("leave room for email: %s", email)
            leave_room(email)
            del ws_sids[request.sid]

socketio.on_namespace(PayDbNamespace(NS))

#
# Private (paydb) API
#

@paydb.route('/user_register', methods=['POST'])
def user_register():
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["email", "password", "first_name", "last_name", "photo", "photo_type"])
    if err_response:
        return err_response
    email, password, first_name, last_name, photo, photo_type = params
    if not utils.is_email(email):
        return bad_request(web_utils.INVALID_EMAIL)
    if not password:
        return bad_request(web_utils.EMPTY_PASSWORD)
    if photo and len(photo) > 50000:
        return bad_request(web_utils.PHOTO_DATA_LARGE)
    req = UserCreateRequest(first_name, last_name, email, photo, photo_type, encrypt_password(password))
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
    user.photo = req.photo
    user.photo_type = req.photo_type
    user.confirmed_at = now
    db.session.delete(req)
    db.session.commit()
    flash('User registered.', 'success')
    return redirect('/')

@paydb.route('/api_key_create', methods=['POST'])
def api_key_create():
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["email", "password", "device_name"])
    if err_response:
        return err_response
    email, password, device_name = params
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

@paydb.route('/api_key_request', methods=['POST'])
def api_key_request():
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["email", "device_name"])
    if err_response:
        return err_response
    email, device_name = params
    user = User.from_email(db.session, email)
    if not user:
        req = ApiKeyRequest(user, device_name)
        return jsonify(dict(token=req.token))
    req = ApiKeyRequest(user, device_name)
    utils.email_api_key_request(logger, req, req.MINUTES_EXPIRY)
    db.session.add(req)
    db.session.commit()
    return jsonify(dict(token=req.token))

@paydb.route('/api_key_claim', methods=['POST'])
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

@paydb.route('/api_key_confirm/<token>/<secret>', methods=['GET', 'POST'])
def api_key_confirm(token=None, secret=None):
    req = ApiKeyRequest.from_token(db.session, token)
    if not req:
        time.sleep(5)
        flash('API KEY request not found.', 'danger')
        return redirect('/')
    if req.secret != secret:
        flash('API KEY code invalid.', 'danger')
        return redirect('/')
    now = datetime.datetime.now()
    if now > req.expiry:
        time.sleep(5)
        flash('API KEY request expired.', 'danger')
        return redirect('/')
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        if not confirm:
            db.session.delete(req)
            db.session.commit()
            flash('API KEY cancelled.', 'success')
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
        flash('API KEY confirmed.', 'success')
        return redirect('/')
    return render_template('paydb/api_key_confirm.html', req=req, perms=Permission.PERMS_ALL)

@paydb.route('/user_info', methods=['POST'])
def user_info():
    sig = request_get_signature()
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["api_key", "nonce", "email"])
    if err_response:
        return err_response
    api_key, nonce, email = params
    res, reason, api_key = check_auth(db.session, api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    if not email:
        email = api_key.user.email
    user = User.from_email(db.session, email)
    if not user:
        time.sleep(5)
        return bad_request(web_utils.AUTH_FAILED)
    if user == api_key.user:
        balance = paydb_core.user_balance(db.session, api_key)
        roles = [role.name for role in api_key.user.roles]
        perms = [perm.name for perm in api_key.permissions]
        return jsonify(dict(email=user.email, balance=balance, photo=user.photo, photo_type=user.photo_type, roles=roles, permissions=perms))
    return jsonify(dict(email=user.email, balance=-1, photo=user.photo, photo_type=user.photo_type, roles=[], permissions=[]))

@paydb.route('/user_transactions', methods=['POST'])
def user_transactions():
    sig = request_get_signature()
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["api_key", "nonce", "offset", "limit"])
    if err_response:
        return err_response
    api_key, nonce, offset, limit = params
    if limit > 1000:
        return bad_request(web_utils.LIMIT_TOO_LARGE)
    res, reason, api_key = check_auth(db.session, api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    if not api_key.has_permission(Permission.PERMISSION_HISTORY):
        return bad_request(web_utils.UNAUTHORIZED)
    txs = PayDbTransaction.related_to_user(db.session, api_key.user, offset, limit)
    txs = [tx.to_json() for tx in txs]
    return jsonify(dict(txs=txs))

@paydb.route('/transaction_create', methods=['POST'])
def transaction_create():
    sig = request_get_signature()
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["api_key", "nonce", "action", "recipient", "amount", "attachment"])
    if err_response:
        return err_response
    api_key, nonce, action, recipient, amount, attachment = params
    res, reason, api_key = check_auth(db.session, api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    tx, error = paydb_core.tx_create_and_play(db.session, api_key, action, recipient, amount, attachment)
    if not tx:
        return bad_request(error)
    tx_event(tx)
    return jsonify(dict(tx=tx.to_json()))

@paydb.route('/transaction_info', methods=['POST'])
def transaction_info():
    sig = request_get_signature()
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["api_key", "nonce", "token"])
    if err_response:
        return err_response
    api_key, nonce, token = params
    res, reason, api_key = check_auth(db.session, api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    tx = PayDbTransaction.from_token(db.session, token)
    if not tx:
        return bad_request(web_utils.INVALID_TX)
    if tx.user != api_key.user and tx.recipient != api_key.user:
        return bad_request(web_utils.UNAUTHORIZED)
    return jsonify(dict(tx=tx.to_json()))
