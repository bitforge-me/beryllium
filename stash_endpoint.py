# pylint: disable=unbalanced-tuple-unpacking

import logging
import time
import datetime

from flask import Blueprint, render_template, request, jsonify, flash, redirect

from app_core import db
from models import UserStash, UserStashRequest
import utils
from web_utils import bad_request, get_json_params
import web_utils

logger = logging.getLogger(__name__)
stash_bp = Blueprint('stash_bp', __name__, template_folder='templates')

@stash_bp.route('/save', methods=['POST'])
def stash_save():
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["key", "email", "iv", "cyphertext", "question"])
    if err_response:
        return err_response
    key, email, iv, cyphertext, question = params
    stash = UserStash.from_email_hash(db.session, key, utils.sha256(email))
    req = UserStashRequest(key, email, iv, cyphertext, question, UserStashRequest.ACTION_SAVE)
    if not stash:
        db.session.add(req)
        db.session.commit()
        utils.email_stash_save_request(logger, email, req, req.MINUTES_EXPIRY)
        logger.info('stash save request %s created', req.token)
    else:
        logger.warning('stash for email %s exists, save request %s not created', email, req.token)
        utils.email_stash_save_exists(logger, email, req)
    return jsonify(dict(token=req.token))

@stash_bp.route('/save_check/<token>')
def stash_save_check(token=None):
    req = UserStashRequest.from_token(db.session, token)
    if not req:
        return jsonify(dict(confirmed=False))
    return jsonify(dict(confirmed=req.created_stash is not None))

@stash_bp.route('/save_confirm/<token>/<secret>', methods=['GET', 'POST'])
def stash_save_confirm(token=None, secret=None):
    req = UserStashRequest.from_token(db.session, token)
    if not req:
        logger.warning('stash request %s not found', token)
        time.sleep(5)
        flash('STASH request not found.', 'danger')
        return redirect('/')
    now = datetime.datetime.now()
    if now > req.expiry:
        time.sleep(5)
        flash('STASH request expired.', 'danger')
        return redirect('/')
    if req.secret != secret:
        flash('STASH code invaid.', 'danger')
        return redirect('/')
    if req.action != req.ACTION_SAVE:
        flash('STASH action invaid.', 'danger')
        return redirect('/')
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        if not confirm:
            db.session.delete(req)
            db.session.commit()
            flash('STASH cancelled.', 'success')
            return redirect('/')
        stash = UserStash(req)
        req.created_stash = stash
        db.session.add(req)
        db.session.add(stash)
        db.session.commit()
        flash('STASH confirmed.', 'success')
        return redirect('/')
    return render_template('stash/stash_save_confirm.html', req=req)

@stash_bp.route('/load', methods=['POST'])
def stash_load():
    content = request.get_json(force=True)
    if content is None:
        return bad_request(web_utils.INVALID_JSON)
    params, err_response = get_json_params(content, ["key", "email"])
    if err_response:
        return err_response
    key, email = params
    stash = UserStash.from_email_hash(db.session, key, utils.sha256(email))
    req = UserStashRequest(key, email, None, None, None, UserStashRequest.ACTION_LOAD)
    if stash:
        utils.email_stash_load_request(logger, email, req, req.MINUTES_EXPIRY)
        db.session.add(req)
        db.session.commit()
        logger.info('stash load request %s created', req.token)
    else:
        logger.warning('stash for email %s does not exist, load request %s not created', email, req.token)
    return jsonify(dict(token=req.token))

@stash_bp.route('/load_check/<token>')
def stash_load_check(token=None):
    confirmed = False
    key = None
    iv = None
    cyphertext = None
    question = None
    req = UserStashRequest.from_token(db.session, token)
    if req:
        confirmed = req.loaded_stash is not None
        if confirmed:
            key = req.loaded_stash.key
            iv = req.loaded_stash.iv
            cyphertext = req.loaded_stash.cyphertext
            question = req.loaded_stash.question
    return jsonify(dict(confirmed=confirmed, key=key, iv=iv, cyphertext=cyphertext, question=question))

@stash_bp.route('/load_confirm/<token>/<secret>', methods=['GET', 'POST'])
def stash_load_confirm(token=None, secret=None):
    req = UserStashRequest.from_token(db.session, token)
    if not req:
        logger.warning('stash request %s not found', token)
        time.sleep(5)
        flash('STASH request not found.', 'danger')
        return redirect('/')
    now = datetime.datetime.now()
    if now > req.expiry:
        time.sleep(5)
        flash('STASH request expired.', 'danger')
        return redirect('/')
    if req.secret != secret:
        flash('STASH code invaid.', 'danger')
        return redirect('/')
    if req.action != req.ACTION_LOAD:
        flash('STASH action invaid.', 'danger')
        return redirect('/')
    if request.method == 'POST':
        confirm = request.form.get('confirm') == 'true'
        if not confirm:
            db.session.delete(req)
            db.session.commit()
            flash('STASH cancelled.', 'success')
            return redirect('/')
        stash = UserStash.from_email_hash(db.session, req.key, req.email_hash)
        req.loaded_stash = stash
        db.session.add(req)
        db.session.commit()
        flash('STASH confirmed.', 'success')
        return redirect('/')
    return render_template('stash/stash_load_confirm.html', req=req)
