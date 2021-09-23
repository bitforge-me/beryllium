import datetime
import logging

import payments_core
import dasset
from models import FiatDbTransaction
import websocket
import utils
import fiatdb_core

logger = logging.getLogger(__name__)

# pylint: disable=too-many-statements
def _fiat_deposit_update(db_session, fiat_deposit):
    logger.info('processing fiat deposit %s (%s)..', fiat_deposit.token, fiat_deposit.status)
    updated_records = []
    # check payment
    if fiat_deposit.status == fiat_deposit.STATUS_CREATED:
        if fiat_deposit.windcave_payment_request:
            payment_req = fiat_deposit.windcave_payment_request
            payments_core.payment_request_status_update(payment_req)
            if payment_req.status == payment_req.STATUS_CANCELLED:
                fiat_deposit.status = fiat_deposit.STATUS_CANCELLED
                updated_records.append(payment_req)
                updated_records.append(fiat_deposit)
                return updated_records
            if payment_req.status == payment_req.STATUS_COMPLETED:
                fiat_deposit.status = fiat_deposit.STATUS_COMPLETED
                ftx = fiatdb_core.tx_create_and_play(db_session, fiat_deposit.user, FiatDbTransaction.ACTION_CREDIT, fiat_deposit.asset, fiat_deposit.amount, f'fiat deposit: {fiat_deposit.token}')
                if ftx:
                    updated_records.append(payment_req)
                    updated_records.append(fiat_deposit)
                    updated_records.append(ftx)
                else:
                    logger.error('failed to create fiatdb transaction for fiat deposit %s', fiat_deposit.token)
                return updated_records
    # check expiry
    if fiat_deposit.status == fiat_deposit.STATUS_CREATED:
        if datetime.datetime.now() > fiat_deposit.expiry:
            fiat_deposit.status = fiat_deposit.STATUS_EXPIRED
            updated_records.append(fiat_deposit)
            return updated_records
    return updated_records

def _email_msg(fiat_deposit, msg):
    amount =  dasset.asset_int_to_dec(fiat_deposit.asset, fiat_deposit.amount)
    amount = dasset.asset_dec_to_str(fiat_deposit.asset, amount)
    return f'Your deposit {fiat_deposit.token} ({amount} {fiat_deposit.asset}) is now {fiat_deposit.status}. \n\n{msg}'

def _fiat_deposit_email(fiat_deposit):
    if fiat_deposit.status == fiat_deposit.STATUS_COMPLETED:
        utils.send_email(logger, 'Deposit Completed', _email_msg(fiat_deposit, ''), fiat_deposit.user.email)
    if fiat_deposit.status == fiat_deposit.STATUS_EXPIRED:
        utils.send_email(logger, 'Deposit Expired', _email_msg(fiat_deposit, ''), fiat_deposit.user.email)

def fiat_deposit_update_and_commit(db_session, fiat_deposit):
    while True:
        updated_records = _fiat_deposit_update(db_session, fiat_deposit)
        # commit db if records updated
        if not updated_records:
            return
        for rec in updated_records:
            db_session.add(rec)
        db_session.commit()
        # send updates
        _fiat_deposit_email(fiat_deposit)
        websocket.fiat_deposit_update_event(fiat_deposit)
