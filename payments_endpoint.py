# pylint: disable=unbalanced-tuple-unpacking
import io
import logging

from flask import Blueprint, request, render_template, flash, redirect, make_response, url_for
from flask_security import roles_accepted

from app_core import db, limiter
from models import PayoutRequest, PayoutGroup, WindcavePaymentRequest, Role
import web_utils
import bnz_ib4b
import payments_core
import depwith

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
    if req.fiat_deposit:
        depwith.fiat_deposit_update_and_commit(db.session, req.fiat_deposit)
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
    if req.fiat_deposit:
        depwith.fiat_deposit_update_and_commit(db.session, req.fiat_deposit)
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

@payments.route('/payouts')
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def payouts():
    suspended = request.args.get('suspended') == 'true'
    if suspended:
        reqs = PayoutRequest.where_status_suspended(db.session)
    else:
        reqs = PayoutRequest.where_status_created(db.session)
    return render_template('payments/payouts.html', payout_requests=reqs, suspended=suspended)

@payments.route('/payout_group/<token>', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def payout_group(token=None):
    group = PayoutGroup.from_token(db.session, token)
    if not group:
        flash('Sorry group not found', category='danger')
        return redirect('/')
    if group.expired:
        flash('Sorry group is expired', category='danger')
        return redirect('/')
    return render_template('payments/payout_group.html', token=token, group=group, payout_requests=group.requests)

@payments.route('/payout_group_create', methods=['POST'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def payout_group_create():
    group = payments_core.payout_group_create()
    if group:
        db.session.commit()
        return redirect(f'/payments/payout_group/{group.token}')
    flash('Sorry group not created', category='danger')
    return redirect('/')

@payments.route('/payout_group_processed', methods=['POST'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def payout_group_processed():
    content = request.form
    token = content['token']
    logger.info('looking for %s', token)
    group = PayoutGroup.from_token(db.session, token)
    if group:
        payments_core.set_payout_requests_complete(group.requests)
        db.session.commit()
        return redirect(f'/payments/payout_group/{token}')
    flash('Sorry group not found', category='danger')
    return redirect('/')

@payments.route('/payout_request_suspend', methods=['POST'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def payout_suspend():
    content = request.form
    token = content['token']
    logger.info('looking for %s', token)
    req = PayoutRequest.from_token(db.session, token)
    if req:
        payments_core.set_payout_request_suspended(req)
        db.session.commit()
        return redirect('/payments/payouts')
    flash('Sorry payout not found', category='danger')
    return redirect('/')

@payments.route('/payout_request_unsuspend', methods=['POST'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def payout_unsuspend():
    content = request.form
    token = content['token']
    logger.info('looking for %s', token)
    req = PayoutRequest.from_token(db.session, token)
    if req:
        payments_core.set_payout_request_created(req)
        db.session.commit()
        return redirect('/payments/payouts')
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
        # ingore already completed
        if req.status == req.STATUS_COMPLETED:
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

@payments.route('/payout_group/BNZ_IB4B_file/<token>', methods=['GET'])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def payout_group_ib4b_file(token=None):
    group = PayoutGroup.from_token(db.session, token)
    if not group:
        flash('Sorry group not found', category='danger')
        return redirect('/')
    return ib4b_response("group_" + group.token, group.requests)
