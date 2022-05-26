# pylint: disable=unbalanced-tuple-unpacking
import os
import sys
import logging

import email_utils
from app_core import app, db
from models import PayoutRequest, PayoutGroup, PayoutGroupRequest

logger = logging.getLogger(__name__)

PAYOUT_SENDER_NAME = os.environ.get('PAYOUT_SENDER_NAME', '')
PAYOUT_SENDER_ACCOUNT = os.environ.get('PAYOUT_SENDER_ACCOUNT', '')
if not PAYOUT_SENDER_NAME:
    logger.error('ERROR: no PAYOUT_SENDER_NAME')
    sys.exit(1)
if not PAYOUT_SENDER_ACCOUNT:
    logger.error('ERROR: no PAYOUT_SENDER_ACCOUNT')
    sys.exit(1)

def payout_create(amount, sender_reference, sender_code, account_name, account_number, reference, code, particulars):
    # create payout request
    req = PayoutRequest('NZD', amount, PAYOUT_SENDER_NAME, PAYOUT_SENDER_ACCOUNT, sender_reference, sender_code, account_name, account_number, reference, code, particulars, app.config['PAYOUT_GROUP_EMAIL'], False)
    return req

def payouts_notification_create():
    reqs = PayoutRequest.where_status_created(db.session)
    # send email
    email_utils.email_payouts_notification(logger, reqs)

def payout_group_create():
    # create payout group
    group = PayoutGroup()
    db.session.add(group)
    db.session.flush()
    reqs = PayoutRequest.where_status_created(db.session)
    for r in reqs:
        group_req = PayoutGroupRequest(group, r)
        db.session.add(group_req)
    # expire old groups
    PayoutGroup.expire_all_but(db.session, group)
    return group

def set_payout_requests_complete(reqs):
    for req in reqs:
        # ignore suspended
        if req.status == req.STATUS_SUSPENDED:
            continue
        req.status = req.STATUS_COMPLETED
        db.session.add(req)

def set_payout_request_suspended(req):
    # ignore not in created state
    if req.status != req.STATUS_CREATED:
        return False
    req.status = req.STATUS_SUSPENDED
    db.session.add(req)
    return True

def set_payout_request_created(req):
    # ignore not in suspended state
    if req.status != req.STATUS_SUSPENDED:
        return False
    req.status = req.STATUS_CREATED
    db.session.add(req)
    return True
