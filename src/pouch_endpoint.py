import logging

from flask import Blueprint, request

from app_core import limiter, db
import web_utils
from models import Remit
import websocket
from email_utils import email_catastrophic_error, send_email
import pouch_core

logger = logging.getLogger(__name__)
pouch = Blueprint('pouch', __name__, template_folder='templates/pouch')
limiter.limit("100/minute")(pouch)

#
# Pouch webhook
#

@pouch.route('/webhook', methods=['POST'])
def webhook():
    if request.method == 'POST':
        sig = request.headers['X-Pouch-Signature']
        if not sig:
            return web_utils.bad_request('signature header not present')
        our_sig = web_utils.create_hmac_sig(pouch_core.API_SECRET, request.data, format='hex')
        if our_sig != sig:
            return web_utils.bad_request(web_utils.AUTH_FAILED)
        if request.is_json:
            try:
                assert request.json
                event = request.json['event']
                ref_id = request.json['payload']['referenceId']
                invoice = pouch_core._parse_invoice(request.json['payload'])
                logger.info('pouch webhook %s, %s', event, ref_id)
                remit = Remit.from_reference_id(db.session, ref_id)
                if not remit:
                    logger.error('invoice not found %s', ref_id)
                    return web_utils.bad_request(web_utils.NOT_FOUND)
                # update remit
                remit.status = invoice.status
                db.session.add(remit)
                db.session.commit()
                # send events
                websocket.remit_update_event(remit, invoice)
                recipient = invoice.recipient
                msg = f'Your remit of {recipient.amount} {recipient.currency} to {recipient.name} has changed status to "{invoice.status}"'
                if invoice.status == pouch_core.PouchInvoiceStatus.failed.value:
                    # automatically process refund
                    res = pouch_core.invoice_refund_deposit(remit)
                    if res.err:
                        err_msg = f'failed to create pouch refund deposit for ({invoice.ref_id}) - {res.err}'
                        logger.error(err_msg)
                        email_catastrophic_error(err_msg)
                    else:
                        crypto_deposit = res.deposit
                        assert crypto_deposit
                        db.session.add(crypto_deposit)
                        db.session.commit()
                        # make pouch refund
                        assert crypto_deposit.wallet_reference
                        res = pouch_core.invoice_refund(ref_id, crypto_deposit.wallet_reference, quiet=True)
                        if res.err:
                            err_msg = f'failed to execute pouch refund for ({invoice.ref_id}) - {res.err}'
                            logger.error(err_msg)
                            email_catastrophic_error(err_msg)
                        else:
                            invoice = res.invoice
                            assert invoice
                            # update status
                            if remit.status != invoice.status:
                                remit.status = invoice.status
                                db.session.add(remit)
                                db.session.commit()
                            # update msg to user
                            msg += '<br><br>Your funds are being refunded automatically'
                send_email('Remit update', msg, remit.user.email)
                return 'ok'
            except Exception:
                logger.error('pouch webhook failed')
                email_catastrophic_error('pouch webhook failed')
    return web_utils.bad_request(web_utils.INVALID_PARAMETER)
