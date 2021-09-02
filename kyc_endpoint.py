# pylint: disable=unbalanced-tuple-unpacking
from io import BytesIO
import logging

import requests
from flask import Blueprint, request, render_template, flash, redirect, make_response, abort

from app_core import app, db, limiter
from models import KycRequest, AplyId
import b2blaze
import websocket

logger = logging.getLogger(__name__)
kyc = Blueprint('kyc', __name__, template_folder='templates')
limiter.limit("100/minute")(kyc)

APLYID_BASE_URL = app.config['APLYID_BASE_URL']
APLYID_API_KEY = app.config['APLYID_API_KEY']
APLYID_API_SECRET = app.config['APLYID_API_SECRET']
APLYID_WEBHOOK_BEARER_TOKEN = app.config['APLYID_WEBHOOK_BEARER_TOKEN']
KYC_BUCKET = app.config['KYC_BUCKET']

#
# Helper functions
#

def aplyid_send_text(phone, token):
    try:
        headers = {'Aply-API-Key': APLYID_API_KEY, 'Aply-Secret': APLYID_API_SECRET}
        params = {'reference': token, 'contact_phone': phone}
        r = requests.post(APLYID_BASE_URL + '/send_text', headers=headers, json=params)
        r.raise_for_status()
        return r.json()['transaction_id']
    except Exception as ex: # pylint: disable=broad-except
        print('failed to get transaction id')
        print(ex)
    return None

def aplyid_download_pdf(transaction_id):
    try:
        headers = {'Aply-API-Key': APLYID_API_KEY, 'Aply-Secret': APLYID_API_SECRET}
        r = requests.get(APLYID_BASE_URL + '/biometric/pdf/%s.pdf' % transaction_id, headers=headers)
        r.raise_for_status()
        return BytesIO(r.content)
    except Exception as ex: # pylint: disable=broad-except
        print('failed to get pdf')
        print(ex)
        print(r.text)
    return None

def backup_aplyid_pdf(token, transaction_id, pdf):
    try:
        api_url, _, auth_token = b2blaze.backblaze_authorize_account()
        bucket_id = b2blaze.backblaze_get_bucket_id(api_url, auth_token, KYC_BUCKET)
        upload_url, upload_auth_token = b2blaze.backblaze_get_upload_url(api_url, auth_token, bucket_id)
        b2blaze.backblaze_upload_file(upload_url, upload_auth_token, f'{token}.pdf', pdf, 'application/pdf')
        return True
    except Exception as ex: # pylint: disable=broad-except
        logger.error('failed to backup pdf')
        logger.error(ex)
    return False

def download_pdf_backup(token):
    try:
        _, download_url, auth_token = b2blaze.backblaze_authorize_account()
        pdf = b2blaze.backblaze_download_file(download_url, auth_token, KYC_BUCKET, f'{token}.pdf')
        return pdf
    except Exception as ex: # pylint: disable=broad-except
        logger.error('failed to download pdf')
        logger.error(ex)
    return None

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
            transaction_id = aplyid_send_text(aplyid_phone, req.token)
            if transaction_id:
                logger.info('aplyid transaction_id: %s', transaction_id)
                # if aplyid object already exists update the transaction_id
                aplyid = req.aplyid
                if aplyid:
                    aplyid.transaction_id = transaction_id
                else:
                    aplyid = AplyId(req, transaction_id)
                db.session.add(aplyid)
                db.session.commit()
                aplyid_transaction_id = transaction_id
            else:
                verification_message = 'unable to send text message, please ensure the mobile number is valid (country code first without the "+", followed by the phone number without any leading zeros "0")'
    # render template
    return render_template('kyc/request.html', token=token, completed=req.status==req.STATUS_COMPLETED, aplyid_transaction_id=aplyid_transaction_id, verification_message=verification_message)

@kyc.route('/aplyid_pdf/<token>', methods=['GET'])
def aplyid_pdf(token=None):
    req = KycRequest.from_token(db.session, token)
    if not req:
        flash('sorry, request not found')
        return redirect('/')
    pdf = download_pdf_backup(token)
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
        pdf = aplyid_download_pdf(transaction_id)
        if not pdf:
            logger.error('aplyid webhook error - unable to download pdf')
            return abort(400, 'sorry, unable to download pdf')
        if not backup_aplyid_pdf(token, transaction_id, pdf):
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
