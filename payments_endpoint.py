# pylint: disable=unbalanced-tuple-unpacking
import io
import logging

from flask import Blueprint, request, render_template, flash, redirect, make_response, url_for

from app_core import db, limiter
from models import PayoutRequest, PayoutGroup, WindcavePaymentRequest
import web_utils
import bnz_ib4b
import payments_core
import broker

logger = logging.getLogger(__name__)
payments = Blueprint('payments', __name__, template_folder='templates')
limiter.limit("100/minute")(payments)

#
# Public payments endpoints
#

@payments.route('/payment/<token>', methods=['GET'])
def payment_interstitial(token=None):
    req = WindcavePaymentRequest.from_token(db.session, token)
    if not req:
        flash('Sorry payment request not found', category='danger')
        return redirect('/')
    if req.status != req.STATUS_CREATED:
        return redirect(url_for('payments.payment', token=token))
    broker.broker_order_update_and_commit(db.session, req.broker_order)
    if req.status != req.STATUS_CREATED:
        return redirect(url_for('payments.payment', token=token))
    return render_template('payments/payment_request.html', token=token, interstitial=True, mock=payments_core.mock())

@payments.route('/payment/mock/<token>', methods=['GET'])
def payment_mock_confirm(token=None):
    if not payments_core.mock():
        return web_utils.bad_request('not found', code=404)
    req = WindcavePaymentRequest.from_token(db.session, token)
    if not req:
        flash('Sorry payment request not found', category='danger')
        return redirect('/')
    payments_core.payment_request_mock_confirm(req)
    broker.broker_order_update_and_commit(db.session, req.broker_order)
    return redirect(url_for('payments.payment', token=token))

@payments.route('/payment/x/<token>', methods=['GET'])
def payment(token=None):
    req = WindcavePaymentRequest.from_token(db.session, token)
    if not req:
        flash('Sorry payment request not found', category='danger')
        return redirect('/')
    completed = req.status == req.STATUS_COMPLETED
    cancelled = req.status == req.STATUS_CANCELLED
    return render_template('payments/payment_request.html', token=token, completed=completed, cancelled=cancelled, req=req)

@payments.route('/payout_group/<token>/<secret>', methods=['GET'])
def payout_group(token=None, secret=None):
    group = PayoutGroup.from_token(db.session, token)
    if not group:
        flash('Sorry request not found', category='danger')
        return redirect('/')
    if group.secret != secret:
        flash('Sorry request not authorized', category='danger')
        return redirect('/')
    if group.expired:
        flash('Sorry group is expired', category='danger')
        return redirect('/')
    return render_template('payments/payout.html', token=token, group=group)

@payments.route('/payout_group_processed', methods=['POST'])
def payout_group_processed():
    content = request.form
    token = content['token']
    secret = content['secret']
    logger.info('looking for %s', token)
    group = PayoutGroup.from_token(db.session, token)
    if group and group.secret == secret:
        payments_core.set_payout_requests_complete(group.requests)
        return redirect(f'/payout_group/{token}/{secret}')
    flash('Sorry group not found', category='danger')
    return redirect('/')

@payments.route('/payout_request_suspend', methods=['POST'])
def payout_suspend():
    content = request.form
    token = content['token']
    secret = content['secret']
    group_token = content['group_token']
    group_secret = content['group_secret']
    logger.info('looking for %s', token)
    req = PayoutRequest.from_token(db.session, token)
    if req and req.secret == secret:
        payments_core.set_payout_request_suspended(req)
        return redirect(f'/payout_group/{group_token}/{group_secret}')
    flash('Sorry payout not found', category='danger')
    return redirect('/')

@payments.route('/payout_request_unsuspend', methods=['POST'])
def payout_unsuspend():
    content = request.form
    token = content['token']
    secret = content['secret']
    group_token = content['group_token']
    group_secret = content['group_secret']
    logger.info('looking for %s', token)
    req = PayoutRequest.from_token(db.session, token)
    if req and req.secret == secret:
        payments_core.set_payout_request_created(req)
        return redirect(f'/payout_group/{group_token}/{group_secret}')
    flash('Sorry payout not found', category='danger')
    return redirect('/')

def ib4b_response(token, reqs):
    # create output
    output = io.StringIO()
    # process requests
    txs = []
    sender_account = ''
    sender = ''
    for req in reqs:
        # ingore already processed
        if req.processed:
            continue
        # ignore suspended
        if req.status == req.STATUS_SUSPENDED:
            continue
        tx = (req.receiver_account, req.amount, req.sender_reference, req.sender_code, req.receiver, req.receiver_reference, req.receiver_code, req.receiver_particulars)
        txs.append(tx)
        sender_account = req.sender_account
        sender = req.sender
    bnz_ib4b.write_txs(output, "", sender_account, sender, txs)
    # return file response
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = "application/octet-stream"
    resp.headers['Content-Disposition'] = f"inline; filename=bnz_{token}.txt"
    return resp

@payments.route('/payout_group/BNZ_IB4B_file/<token>/<secret>', methods=['GET'])
def payout_group_ib4b_file(token=None, secret=None):
    group = PayoutGroup.from_token(db.session, token)
    if not group:
        flash('Sorry group not found', category='danger')
        return redirect('/')
    if group.secret != secret:
        flash('Sorry group not authorized', category='danger')
        return redirect('/')
    return ib4b_response("group_" + group.token, group.requests)

@payments.route('/payout_processed_to_completed')
def payout_processed_to_completed():
    count = 0
    for req in PayoutRequest.where_status_processed(db.session):
        req.status = req.STATUS_COMPLETED
        db.session.add(req)
        count += 1
    db.session.commit()
    return str(count)
