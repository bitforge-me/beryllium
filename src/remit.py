import logging

from sqlalchemy.orm.session import Session

import assets
from models import BalanceUpdate, Remit
import websocket
import email_utils
import coordinator

import pouch_core
import depwith

logger = logging.getLogger(__name__)

#TODO:
# - analyze the states and how they change
# - how does user recover from failure state?
# - how does admin recover from failure state?

def _update_remit_and_commit(db_session: Session, remit: Remit) -> BalanceUpdate | None:
    crypto_withdrawal: BalanceUpdate | None = None
    # get pouch invoice
    res = pouch_core.invoice_status(remit.reference_id, quiet=True)
    if res.err:
        logger.error('failed to get remit invoice status - %s', res.err.message)
        return
    assert res.invoice
    invoice = res.invoice
    recipient = invoice.recipient
    msg = f'Your remit of {recipient.amount} {recipient.currency} to {recipient.name} has changed status to "{invoice.status}"'
    updated = False
    # check remit status
    if remit.status == remit.STATUS_EXCHANGING:
        if not remit.order:
            err_msg = f'remit order does not exist ({remit.token})'
            logger.error(err_msg)
            email_utils.email_catastrophic_error(err_msg)
            return
        if remit.order.status != remit.order.STATUS_COMPLETED:
            err_msg = f'remit order not yet completed ({remit.order.token})'
            logger.error(err_msg)
            email_utils.email_catastrophic_error(err_msg)
            return
        remit.status = remit.STATUS_SENDING  # now we follow into next status
        updated = True
    if remit.status == remit.STATUS_SENDING:
        if not remit.withdrawal:
            # create withdrawal
            amount_dec = assets.asset_int_to_dec(assets.BTC.symbol, remit.amount)
            crypto_withdrawal, err_response = depwith.crypto_withdrawal_create(db_session, remit.user, assets.BTC.symbol, assets.BTCLN.symbol, amount_dec, invoice.bolt11, create_confirmation=False)
            if err_response:
                logger.error(err_response)
            assert crypto_withdrawal
            websocket.crypto_withdrawal_new_event(crypto_withdrawal)
            # add withdrawal to remit
            remit.withdrawal = crypto_withdrawal
            db_session.add(remit)
            db_session.commit()
    # check invoice status
    if invoice.status == pouch_core.PouchInvoiceStatus.completed.value:
        remit.status = remit.STATUS_COMPLETED
        updated = True
    if invoice.status == pouch_core.PouchInvoiceStatus.expired.value:
        remit.status = remit.STATUS_EXPIRED
        updated = True
    if invoice.status == pouch_core.PouchInvoiceStatus.failed.value:
        if remit.status != remit.STATUS_REFUNDED:
            remit.status = remit.STATUS_REFUNDED
            # automatically process refund
            updated = True
            res = pouch_core.invoice_refund_deposit(remit)
            if res.err:
                err_msg = f'failed to create pouch refund deposit for ({invoice.ref_id}) - {res.err}'
                logger.error(err_msg)
                email_utils.email_catastrophic_error(err_msg)
            else:
                crypto_deposit = res.deposit
                assert crypto_deposit
                db_session.add(crypto_deposit)
                db_session.commit()
                # make pouch refund
                assert crypto_deposit.wallet_reference
                res = pouch_core.invoice_refund(remit.reference_id, crypto_deposit.wallet_reference, quiet=True)
                if res.err:
                    err_msg = f'failed to execute pouch refund for ({invoice.ref_id}) - {res.err}'
                    logger.error(err_msg)
                    email_utils.email_catastrophic_error(err_msg)
                else:
                    invoice = res.invoice
                    assert invoice
                    # update msg to user
                    msg += '<br><br>Your funds are being refunded automatically'
    db_session.add(remit)
    db_session.commit()
    # send events
    if updated:
        websocket.remit_update_event(remit, invoice)
        email_utils.send_email('Remit update', msg, remit.user.email)
    return crypto_withdrawal

def remit_update(db_session: Session, token: str):
    crypto_withdrawal: BalanceUpdate | None
    with coordinator.lock:
        remit = Remit.from_token(db_session, token)
        if not remit:
            logger.error('remit not found %s', token)
            return
        crypto_withdrawal = _update_remit_and_commit(db_session, remit)
    if crypto_withdrawal:
        depwith.crypto_withdrawal_update(db_session, crypto_withdrawal.token)

def remits_update(db_session: Session):
    crypto_withdrawals = []
    with coordinator.lock:
        remits = Remit.all_active(db_session)
        logger.info('num remits: %d', len(remits))
        for remit in remits:
            crypto_withdrawal = _update_remit_and_commit(db_session, remit)
            if crypto_withdrawal:
                crypto_withdrawals.append(crypto_withdrawal)
    for crypto_withdrawal in crypto_withdrawals:
        depwith.crypto_withdrawal_update(db_session, crypto_withdrawal.token)
