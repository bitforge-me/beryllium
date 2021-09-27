# pylint: disable=unbalanced-tuple-unpacking

import logging
import time

from flask import Blueprint, jsonify

import web_utils
from web_utils import auth_request_get_params, bad_request, auth_request, auth_request_get_single_param
import utils
from app_core import app, db, limiter
from models import User, Role, Referral

logger = logging.getLogger(__name__)
reward = Blueprint('reward', __name__, template_folder='templates')
limiter.limit("100/minute")(reward)
use_referrals = app.config["USE_REFERRALS"]

#
# Private (reward) API
#

@reward.route('/referral_config', methods=['POST'])
def referral_config():
    if not use_referrals:
        return bad_request(web_utils.NOT_AVAILABLE)
    _, err_response = auth_request(db)
    if err_response:
        return err_response
    reward_sender_type = app.config["REFERRAL_REWARD_TYPE_SENDER"]
    reward_sender = app.config["REFERRAL_REWARD_SENDER"]
    reward_recipient_type = app.config["REFERRAL_REWARD_TYPE_RECIPIENT"]
    reward_recipient = app.config["REFERRAL_REWARD_RECIPIENT"]
    recipient_min_spend = app.config["REFERRAL_RECIPIENT_MIN_SPEND"]
    spend_asset = app.config["REFERRAL_SPEND_ASSET"]
    return jsonify(dict(reward_sender_type=reward_sender_type, reward_sender=reward_sender, reward_recipient_type=reward_recipient_type, reward_recipient=reward_recipient, recipient_min_spend=recipient_min_spend, spend_asset=spend_asset))

@reward.route('/referral_create', methods=['POST'])
def referral_create():
    if not use_referrals:
        return bad_request(web_utils.NOT_AVAILABLE)
    recipient, api_key, err_response = auth_request_get_single_param(db, "recipient")
    if err_response:
        return err_response
    if not utils.is_email(recipient):
        return bad_request(web_utils.INVALID_EMAIL)
    recipient = recipient.lower()
    user = User.from_email(db.session, recipient)
    if user:
        time.sleep(5)
        return bad_request(web_utils.USER_EXISTS)
    reward_sender_type = app.config["REFERRAL_REWARD_TYPE_SENDER"]
    reward_sender = app.config["REFERRAL_REWARD_SENDER"]
    reward_recipient_type = app.config["REFERRAL_REWARD_TYPE_RECIPIENT"]
    reward_recipient = app.config["REFERRAL_REWARD_RECIPIENT"]
    recipient_min_spend = app.config["REFERRAL_RECIPIENT_MIN_SPEND"]
    ref = Referral(api_key.user, recipient, reward_sender_type, reward_sender, reward_recipient_type, reward_recipient, recipient_min_spend)
    utils.email_referral(logger, ref)
    db.session.add(ref)
    db.session.commit()
    return 'ok'

@reward.route('/referral_remind', methods=['POST'])
def referral_remind():
    if not use_referrals:
        return bad_request(web_utils.NOT_AVAILABLE)
    token, api_key, err_response = auth_request_get_single_param(db, "token")
    if err_response:
        return err_response
    ref = Referral.from_token_user(db.session, token, api_key.user)
    if not ref:
        return bad_request(web_utils.NOT_FOUND)
    if ref.status != ref.STATUS_CREATED:
        return bad_request(web_utils.NOT_FOUND)
    utils.email_referral(logger, ref)
    return 'ok'

@reward.route('/referral_list', methods=['POST'])
def referral_list():
    if not use_referrals:
        return bad_request(web_utils.NOT_AVAILABLE)
    params, api_key, err_response = auth_request_get_params(db, ['offset', 'limit'])
    if err_response:
        return err_response
    offset, limit = params
    refs = Referral.from_user(db.session, api_key.user, offset, limit)
    refs = [ref.to_json() for ref in refs]
    total = Referral.total_for_user(db.session, api_key.user)
    return jsonify(dict(referrals=refs, offset=offset, limit=limit, total=total))

@reward.route('/referral_validate', methods=['POST'])
def referral_validate():
    if not use_referrals:
        return bad_request(web_utils.NOT_AVAILABLE)
    token, api_key, err_response = auth_request_get_single_param(db, "token")
    if err_response:
        return err_response
    if not api_key.user.has_role(Role.ROLE_ADMIN) and not api_key.user.has_role(Role.ROLE_REFERRAL_CLAIMER):
        return bad_request(web_utils.UNAUTHORIZED)
    ref = Referral.from_token(db.session, token)
    if not ref:
        return bad_request(web_utils.NOT_FOUND)
    if ref.status != ref.STATUS_CREATED:
        return bad_request(web_utils.NOT_FOUND)
    return jsonify(dict(referral=ref.to_json()))

@reward.route('/referral_claim', methods=['POST'])
def referral_claim():
    if not use_referrals:
        return bad_request(web_utils.NOT_AVAILABLE)
    token, api_key, err_response = auth_request_get_single_param(db, "token")
    if err_response:
        return err_response
    if not api_key.user.has_role(Role.ROLE_ADMIN) and not api_key.user.has_role(Role.ROLE_REFERRAL_CLAIMER):
        return bad_request(web_utils.UNAUTHORIZED)
    ref = Referral.from_token(db.session, token)
    if not ref:
        return bad_request(web_utils.NOT_FOUND)
    if ref.status != ref.STATUS_CREATED:
        return bad_request(web_utils.NOT_FOUND)
    # send referral rewards
    #TODO: create/send reward

    ref.status = ref.STATUS_CLAIMED
    db.session.add(ref)
    db.session.commit()
    return jsonify(dict(referral=ref.to_json()))
