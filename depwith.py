from datetime import datetime
import logging

import payments_core
import dasset
import assets
from models import CryptoAddress, CryptoDeposit, CryptoWithdrawal, FiatDbTransaction, FiatDeposit, FiatWithdrawal
import websocket
import email_utils
import fiatdb_core
import coordinator

logger = logging.getLogger(__name__)

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
                ftx = fiatdb_core.tx_create(db_session, fiat_deposit.user, FiatDbTransaction.ACTION_CREDIT, fiat_deposit.asset, fiat_deposit.amount, f'fiat deposit: {fiat_deposit.token}')
                if ftx:
                    updated_records.append(payment_req)
                    updated_records.append(fiat_deposit)
                    updated_records.append(ftx)
                else:
                    logger.error('failed to create fiatdb transaction for fiat deposit %s', fiat_deposit.token)
                return updated_records
    # check expiry
    if fiat_deposit.status == fiat_deposit.STATUS_CREATED:
        if datetime.now() > fiat_deposit.expiry:
            fiat_deposit.status = fiat_deposit.STATUS_EXPIRED
            updated_records.append(fiat_deposit)
            return updated_records
    return updated_records

def _fiat_deposit_email_msg(fiat_deposit, msg):
    amount =  assets.asset_int_to_dec(fiat_deposit.asset, fiat_deposit.amount)
    amount = assets.asset_dec_to_str(fiat_deposit.asset, amount)
    return f'Your deposit {fiat_deposit.token} ({amount} {fiat_deposit.asset}) is now {fiat_deposit.status}. \n\n{msg}'

def _fiat_deposit_email(fiat_deposit):
    if fiat_deposit.status == fiat_deposit.STATUS_COMPLETED:
        email_utils.send_email(logger, 'Deposit Completed', _fiat_deposit_email_msg(fiat_deposit, ''), fiat_deposit.user.email)
    if fiat_deposit.status == fiat_deposit.STATUS_EXPIRED:
        email_utils.send_email(logger, 'Deposit Expired', _fiat_deposit_email_msg(fiat_deposit, ''), fiat_deposit.user.email)

def fiat_deposit_update_and_commit(db_session, deposit):
    while True:
        with coordinator.lock:
            updated_records = _fiat_deposit_update(db_session, deposit)
            # commit db if records updated
            if not updated_records:
                return
            for rec in updated_records:
                db_session.add(rec)
            db_session.commit()
        # send updates
        _fiat_deposit_email(deposit)
        websocket.fiat_deposit_update_event(deposit)

def fiat_deposits_update(db_session):
    deposits = FiatDeposit.all_active(db_session)
    logger.info('num deposits: %d', len(deposits))
    for deposit in deposits:
        fiat_deposit_update_and_commit(db_session, deposit)

def _fiat_withdrawal_update(fiat_withdrawal):
    logger.info('processing fiat withdrawal %s (%s)..', fiat_withdrawal.token, fiat_withdrawal.status)
    updated_records = []
    # check payout
    if fiat_withdrawal.status == fiat_withdrawal.STATUS_CREATED:
        if fiat_withdrawal.payout_request:
            payout_request = fiat_withdrawal.payout_request
            if payout_request.status == payout_request.STATUS_COMPLETED:
                fiat_withdrawal.status = fiat_withdrawal.STATUS_COMPLETED
                updated_records.append(fiat_withdrawal)
                return updated_records
    return updated_records

def _fiat_withdrawal_email_msg(fiat_withdrawal, msg):
    amount =  assets.asset_int_to_dec(fiat_withdrawal.asset, fiat_withdrawal.amount)
    amount = assets.asset_dec_to_str(fiat_withdrawal.asset, amount)
    return f'Your withdrawal {fiat_withdrawal.token} ({amount} {fiat_withdrawal.asset}) is now {fiat_withdrawal.status}. \n\n{msg}'

def _fiat_withdrawal_email(fiat_withdrawal):
    if fiat_withdrawal.status == fiat_withdrawal.STATUS_COMPLETED:
        email_utils.send_email(logger, 'Withdrawal Completed', _fiat_withdrawal_email_msg(fiat_withdrawal, ''), fiat_withdrawal.user.email)

def fiat_withdrawal_update_and_commit(db_session, withdrawal):
    while True:
        with coordinator.lock:
            updated_records = _fiat_withdrawal_update(withdrawal)
            # commit db if records updated
            if not updated_records:
                return
            for rec in updated_records:
                db_session.add(rec)
            db_session.commit()
        # send updates
        _fiat_withdrawal_email(withdrawal)
        websocket.fiat_withdrawal_update_event(withdrawal)

def fiat_withdrawals_update(db_session):
    withdrawals = FiatWithdrawal.all_active(db_session)
    logger.info('num withdrawals: %d', len(withdrawals))
    for withdrawal in withdrawals:
        fiat_withdrawal_update_and_commit(db_session, withdrawal)

def _crypto_deposit_email_msg(deposit, verb, msg):
    amount = assets.asset_int_to_dec(deposit.asset, deposit.amount)
    amount = assets.asset_dec_to_str(deposit.asset, amount)
    return f'Your deposit {deposit.txid} ({amount} {deposit.asset}) is now {verb}. \n\n{msg}'

def _crypto_deposit_email(deposit):
    if deposit.confirmed:
        email_utils.send_email(logger, 'Deposit Confirmed', _crypto_deposit_email_msg(deposit, 'confirmed', ''), deposit.user.email)
    else:
        email_utils.send_email(logger, 'Deposit Incoming', _crypto_deposit_email_msg(deposit, 'incoming', ''), deposit.user.email)

def crypto_deposits_check(db_session):
    # query for list of addresses that need to be checked
    addrs = CryptoAddress.need_to_be_checked(db_session)
    # sort in to groups of assets for each user
    user_assets = {}
    for addr in addrs:
        if addr.user.email not in user_assets:
            user_assets[addr.user.email] = addr.user, []
        _, asset_list = user_assets[addr.user.email]
        if addr.asset not in asset_list:
            asset_list.append(addr.asset)
        # update checked at time of CryptoAddress
        addr.checked_at = int(datetime.timestamp(datetime.now()))
        db_session.add(addr)
    # check for new deposits, update existing deposits
    new_crypto_deposits = []
    updated_crypto_deposits = []
    for user, asset_list in user_assets.values():
        if not user.dasset_subaccount:
            logger.error('user %s dasset subaccount does not exist', user.email)
            continue
        for asset in asset_list:
            dasset_deposits = dasset.crypto_deposits(asset, user.dasset_subaccount.subaccount_id)
            for dasset_deposit in dasset_deposits:
                with coordinator.lock:
                    completed = dasset.crypto_deposit_completed(dasset_deposit)
                    crypto_deposit = CryptoDeposit.from_txid(db_session, dasset_deposit.txid)
                    if not crypto_deposit:
                        amount_int = assets.asset_dec_to_int(asset, dasset_deposit.amount)
                        crypto_deposit = CryptoDeposit(user, asset, amount_int, dasset_deposit.id, dasset_deposit.txid, completed)
                        new_crypto_deposits.append(crypto_deposit)
                    elif not crypto_deposit.confirmed and completed:
                        # if deposit now completed transfer the funds to the master account
                        if not dasset.transfer(None, user.dasset_subaccount.subaccount_id, asset, dasset_deposit.amount):
                            logger.error('failed to transfer funds from subaccount to master %s', dasset_deposit.id)
                            continue
                        # and credit the users account
                        ftx = fiatdb_core.tx_create(db_session, user, FiatDbTransaction.ACTION_CREDIT, asset, amount_int, f'crypto deposit: {crypto_deposit.token}')
                        if not ftx:
                            logger.error('failed to create fiatdb transaction for crypto deposit %s', crypto_deposit.token)
                            continue
                        db_session.add(ftx)
                        # update crypto deposit
                        crypto_deposit.confirmed = completed
                        updated_crypto_deposits.append(crypto_deposit)
                    if not crypto_deposit.crypto_address:
                        addr = CryptoAddress.from_addr(db_session, dasset_deposit.address)
                        if addr:
                            crypto_deposit.crypto_address = addr
                    db_session.add(crypto_deposit)
                    db_session.commit()
    # send updates
    for deposit in new_crypto_deposits:
        _crypto_deposit_email(deposit)
        websocket.crypto_deposit_new_event(deposit)
    for deposit in updated_crypto_deposits:
        _crypto_deposit_email(deposit)
        websocket.crypto_deposit_update_event(deposit)

def _crypto_withdrawal_update(crypto_withdrawal):
    logger.info('processing crypto withdrawal %s (%s)..', crypto_withdrawal.token, crypto_withdrawal.status)
    updated_records = []
    # check payout
    if crypto_withdrawal.status == crypto_withdrawal.STATUS_CREATED:
        # check exchange withdrawal
        if dasset.crypto_withdrawal_status_check(crypto_withdrawal.exchange_reference):
            crypto_withdrawal.status = crypto_withdrawal.STATUS_COMPLETED
            updated_records.append(crypto_withdrawal)
        return updated_records
    return updated_records

def _crypto_withdrawal_email_msg(crypto_withdrawal, msg):
    amount =  assets.asset_int_to_dec(crypto_withdrawal.asset, crypto_withdrawal.amount)
    amount = assets.asset_dec_to_str(crypto_withdrawal.asset, amount)
    return f'Your withdrawal {crypto_withdrawal.token} ({amount} {crypto_withdrawal.asset}) is now {crypto_withdrawal.status}. \n\n{msg}'

def _crypto_withdrawal_email(crypto_withdrawal):
    if crypto_withdrawal.status == crypto_withdrawal.STATUS_COMPLETED:
        email_utils.send_email(logger, 'Withdrawal Completed', _crypto_withdrawal_email_msg(crypto_withdrawal, ''), crypto_withdrawal.user.email)

def crypto_withdrawal_update_and_commit(db_session, withdrawal):
    while True:
        with coordinator.lock:
            updated_records = _crypto_withdrawal_update(withdrawal)
            # commit db if records updated
            if not updated_records:
                return
            for rec in updated_records:
                db_session.add(rec)
            db_session.commit()
        # send updates
        _crypto_withdrawal_email(withdrawal)
        websocket.crypto_withdrawal_update_event(withdrawal)

def crypto_withdrawals_update(db_session):
    withdrawals = CryptoWithdrawal.all_active(db_session)
    logger.info('num withdrawals: %d', len(withdrawals))
    for withdrawal in withdrawals:
        crypto_withdrawal_update_and_commit(db_session, withdrawal)
