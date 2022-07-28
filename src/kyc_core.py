from io import BytesIO
import logging

from app_core import app, db
from models import AplyId, KycRequest
import b2blaze
import httpreq

logger = logging.getLogger(__name__)

APLYID_BASE_URL = app.config['APLYID_BASE_URL']
APLYID_API_KEY = app.config['APLYID_API_KEY']
APLYID_API_SECRET = app.config['APLYID_API_SECRET']
KYC_BUCKET = app.config['KYC_BUCKET']

#
# Helper functions
#

def aplyid_send_text(mobile_number: str, token: str):
    try:
        headers = {'Aply-API-Key': APLYID_API_KEY, 'Aply-Secret': APLYID_API_SECRET}
        params = {'reference': token, 'contact_phone': mobile_number}
        r = httpreq.post(APLYID_BASE_URL + '/send_text', headers=headers, json=params)
        r.raise_for_status()
        return r.json()['transaction_id']
    except Exception as ex:
        logger.error('failed to get transaction id', ex)
    return None

def aplyid_request_init(req: KycRequest, mobile_number: str):
    transaction_id = aplyid_send_text(mobile_number, req.token)
    if transaction_id:
        logger.info('aplyid transaction_id: %s', transaction_id)
        # if aplyid object already exists update the transaction_id
        aplyid = req.aplyid
        if aplyid:
            aplyid.transaction_id = transaction_id
        else:
            aplyid = AplyId(req, transaction_id)
        db.session.add(aplyid)
        return transaction_id
    return None

def aplyid_download_pdf(transaction_id: str):
    r = None
    try:
        headers = {'Aply-API-Key': APLYID_API_KEY, 'Aply-Secret': APLYID_API_SECRET}
        r = httpreq.get(APLYID_BASE_URL + f'/biometric/pdf/{transaction_id}.pdf', headers=headers)
        r.raise_for_status()
        return BytesIO(r.content)
    except Exception as ex:
        logger.error('failed to get pdf')
        logger.error(ex)
        if r:
            logger.error(r.text)
    return None

def backup_aplyid_pdf(token: str, transaction_id: str, pdf: BytesIO):
    try:
        api_url, _, auth_token = b2blaze.backblaze_authorize_account()
        bucket_id = b2blaze.backblaze_get_bucket_id(api_url, auth_token, KYC_BUCKET)
        upload_url, upload_auth_token = b2blaze.backblaze_get_upload_url(api_url, auth_token, bucket_id)
        b2blaze.backblaze_upload_file(upload_url, upload_auth_token, f'{token}.pdf', pdf, 'application/pdf')
        return True
    except Exception as ex:
        logger.error('failed to backup pdf')
        logger.error(ex)
    return False

def download_pdf_backup(token):
    try:
        _, download_url, auth_token = b2blaze.backblaze_authorize_account()
        pdf = b2blaze.backblaze_download_file(download_url, auth_token, KYC_BUCKET, f'{token}.pdf')
        return pdf
    except Exception as ex:
        logger.error('failed to download pdf')
        logger.error(ex)
    return None
