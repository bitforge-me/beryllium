import logging

from flask import Blueprint, request, render_template, flash, redirect, make_response, abort

from app_core import app, db, limiter
from models import KycRequest
import websocket
import kyc_core

logger = logging.getLogger(__name__)
kyc = Blueprint('kyc', __name__, template_folder='templates')
limiter.limit("100/minute")(kyc)

APLYID_WEBHOOK_BEARER_TOKEN = app.config['APLYID_WEBHOOK_BEARER_TOKEN']

#
# Public kyc endpoints
#

@kyc.route('/request/<token>', methods=['GET', 'POST'])
def request_start(token=None):
    req = KycRequest.from_token(db.session, token)
    if not req:
        flash('Sorry kyc request not found', category='danger')
        return redirect('/')
    # process any posted data
    aplyid_transaction_id = None
    if req.aplyid:
        aplyid_transaction_id = req.aplyid.transaction_id
    verification_message = None
    if request.method == 'POST':
        aplyid_phone = request.form.get('aplyidPhone')
        if aplyid_phone:
            logger.info('kyc_request token: %s, aplyid_phone: %s', req.token, aplyid_phone)
            transaction_id = kyc_core.aplyid_request_init(req, aplyid_phone)
            if transaction_id:
                db.session.commit()
                aplyid_transaction_id = transaction_id
            else:
                verification_message = 'unable to send text message, please ensure the mobile number is valid (country code first without the "+", followed by the phone number without any leading zeros "0")'
    # render template
    return render_template('kyc/request.html', token=token, completed=req.status == req.STATUS_COMPLETED, aplyid_transaction_id=aplyid_transaction_id, verification_message=verification_message)

@kyc.route('/aplyid_pdf/<token>', methods=['GET'])
def aplyid_pdf(token=None):
    req = KycRequest.from_token(db.session, token)
    if not req:
        flash('sorry, request not found', category='danger')
        return redirect('/')
    pdf = kyc_core.download_pdf_backup(token)
    if not pdf:
        return 'failed to download pdf'
    response = make_response(pdf)
    response.headers.set('Content-Type', 'application/pdf')
    return response

@kyc.route('/aplyid_webhook', methods=['POST'])
def aplyid_webhook():
    logger.info('aplyid webhook entry')
    # check bearer token
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return abort(403, 'auth header not present')
    parts = auth_header.split(' ')
    if len(parts) != 2 or parts[0] != 'Bearer' or parts[1] != APLYID_WEBHOOK_BEARER_TOKEN:
        return abort(403)
    logger.info('aplyid webhook authorized')
    # parse body
    if not request.is_json:
        logger.info('aplyid webhook not json')
        return 'ok'
    data = request.get_json(silent=True)
    if not data:
        logger.info('aplyid webhook payload is empty or was not parsable')
        return 'ok'
    logger.info('aplyid webhook, event: %s, msg: %s', data['event'], data['message'])
    if (data['event'] == 'completed' or data['event'] == 'updated') and \
       'verification' in data and \
       (data['verification']['status'] == 'pass' or data['verification']['status'] == 'reviewed'):
        token = data['reference']
        transaction_id = data['transaction_id']
        logger.info('aplyid verification completed - %s, %s', token, transaction_id)
        req = KycRequest.from_token(db.session, token)
        if not req:
            logger.error('aplyid webhook error - request not found (%s)', token)
            return abort(404, 'sorry, request not found')
        if not req.aplyid or req.aplyid.transaction_id != transaction_id:
            logger.error('aplyid webhook error - transaction id does not match')
            return abort(404, 'sorry, transaction id does not match')
        req.status = req.STATUS_COMPLETED
        db.session.add(req)
        db.session.commit()
        websocket.user_info_event(req.user)
        logger.info('aplyid webhook completed - updated db')
        # save pdf
        pdf = kyc_core.aplyid_download_pdf(transaction_id)
        if not pdf:
            logger.error('aplyid webhook error - unable to download pdf')
            return abort(400, 'sorry, unable to download pdf')
        if not kyc_core.backup_aplyid_pdf(token, transaction_id, pdf):
            logger.error('aplyid webhook error - unable to backup pdf')
            return abort(400, 'sorry, unable to backup pdf')
    return 'ok'

#@kyc.route('/test_pdf_upload')
#def test_pdf_upload():
#    pdf = BytesIO(b'hello dan')
#    return str(backup_aplyid_pdf('token', 'transaction_id', pdf))
#
#@kyc.route('/test_pdf_download_upload/<transaction_id>')
#def test_pdf_download_upload(transaction_id):
#    pdf = aplyid_download_pdf(transaction_id)
#    if not pdf:
#        return 'failed to download pdf'
#    return str(backup_aplyid_pdf('token', transaction_id, pdf))
#
#@kyc.route('/test_pdf_download/<transaction_id>')
#def test_pdf_download(transaction_id):
#    from flask import send_file
#    pdf = aplyid_download_pdf(transaction_id)
#    if not pdf:
#        return 'failed to download pdf'
#    return send_file(pdf, attachment_filename='test.pdf', mimetype='application/pdf')
#
#@kyc.route('/test_send_text/<number>')
#def test_send_text(number):
#    transaction_id = aplyid_send_text(number, 't')
#    if not transaction_id:
#        return 'failed to send text'
#    return transaction_id
