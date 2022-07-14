import logging

import email_utils
from app_core import app, db
from models import PayoutRequest, PayoutGroup, PayoutGroupRequest

logger = logging.getLogger(__name__)


def payout_create(amount, reference, code, address_book):
    # create payout request
    req = PayoutRequest(
        'NZD',
        amount,
        reference,
        code,
        app.config['PAYOUT_GROUP_EMAIL'],
        False,
        address_book,
    )
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


def set_payout_request_complete(req):
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
