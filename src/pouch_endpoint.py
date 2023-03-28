import logging

from flask import Blueprint, request

from app_core import limiter, db, csrf
import web_utils
from models import Remit
from email_utils import email_catastrophic_error
import pouch_core
import tasks

logger = logging.getLogger(__name__)
pouch = Blueprint('pouch', __name__, template_folder='templates/pouch')
limiter.limit("100/minute")(pouch)

#
# Pouch webhook
#

@pouch.route('/webhook', methods=['GET', 'POST'])
@csrf.exempt
def webhook():
    if request.method == 'POST':
        sig = request.headers['X-Pouch-Signature']
        if not sig:
            logger.error('signature header not present')
            return web_utils.bad_request(web_utils.AUTH_FAILED)
        logger.info('    sig: %s', sig)
        our_sig = web_utils.create_hmac_sig(pouch_core.API_SECRET, request.data, format='hex')
        logger.info('out_sig: %s', our_sig)
        if our_sig != sig:
            logger.error('authentication failed')
            return web_utils.bad_request(web_utils.AUTH_FAILED)
        if request.is_json:
            try:
                assert request.json
                event = request.json['event']
                ref_id = request.json['payload']['referenceId']
                invoice = pouch_core._parse_invoice(request.json['payload'])
                logger.info('pouch webhook "%s", %s', event, ref_id)
                remit = Remit.from_reference_id(db.session, ref_id)
                if not remit:
                    logger.error('invoice not found %s', ref_id)
                    return web_utils.bad_request(web_utils.NOT_FOUND)
                tasks.task_manager.one_off('update remit', tasks.update_remit, [remit.token])
                return 'ok'
            except Exception as e:
                logger.error('pouch webhook failed')
                email_catastrophic_error(f'pouch webhook failed - {e}')
    return web_utils.bad_request(web_utils.INVALID_PARAMETER)
