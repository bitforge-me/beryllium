from datetime import datetime, timedelta
import logging
from typing import Dict, Tuple

from sqlalchemy.orm.session import Session
from ln_wallet_endpoint import sign_psbt

import windcave
import dasset
import assets
from models import BrokerOrder, FiatDepositCode, CryptoAddress, BalanceUpdate, FiatDbTransaction, User, CrownPayment, WithdrawalConfirmation
import websocket
import email_utils
import fiatdb_core
import coordinator
import wallet
import tripwire
import utils
import crown_financial
import payouts_core
import broker

logger = logging.getLogger(__name__)

def withdrawal_cancel(withdrawal: BalanceUpdate, reason: str):
    # cancel withdrawal
    assert withdrawal.status in (withdrawal.STATUS_CREATED, withdrawal.STATUS_AUTHORIZED)
    withdrawal.status = withdrawal.STATUS_CANCELLED
    # refund user
    asset = withdrawal.asset
    amount_int = withdrawal.amount
    fee_int = withdrawal.fee
    amount_plus_fee_int = amount_int + fee_int
    asset_type = 'crypto' if assets.asset_is_crypto(asset) else 'fiat'
    ftx = fiatdb_core.tx_create(withdrawal.user, FiatDbTransaction.ACTION_CREDIT, asset, amount_plus_fee_int, f'{asset_type} withdrawal refund - {reason}: {withdrawal.token}')
    withdrawal.balance_tx_cancel = ftx
    return ftx

# -------------

def _fiat_deposit_autobuy_failure_email(fiat_deposit: BalanceUpdate, code: FiatDepositCode):
    amount = assets.asset_int_to_dec(fiat_deposit.asset, fiat_deposit.amount)
    amount_str = assets.asset_dec_to_str(fiat_deposit.asset, amount)
    msg = f'Your deposit is being processed but we failed to automatically create a buy order for {code.autobuy_asset} using the funds deposited ({amount_str} {fiat_deposit.asset}). Sorry for the inconvenience.'
    email_utils.send_email('Deposit Autobuy Failed', msg, fiat_deposit.user.email)

def _fiat_deposit_update(db_session: Session, fiat_deposit: BalanceUpdate):
    logger.info('processing fiat deposit %s (%s)..', fiat_deposit.token, fiat_deposit.status)
    updated_records = []
    # check payment
    if fiat_deposit.status == fiat_deposit.STATUS_CREATED:
        # windcave payments
        if fiat_deposit.windcave_payment_request:
            payment_req = fiat_deposit.windcave_payment_request
            windcave.payment_request_status_update(payment_req)
            if payment_req.status == payment_req.STATUS_CANCELLED:
                fiat_deposit.status = fiat_deposit.STATUS_CANCELLED
                updated_records.append(payment_req)
                updated_records.append(fiat_deposit)
                return updated_records
            if payment_req.status == payment_req.STATUS_COMPLETED:
                fiat_deposit.status = fiat_deposit.STATUS_COMPLETED
                ftx = fiatdb_core.tx_create(fiat_deposit.user, FiatDbTransaction.ACTION_CREDIT, fiat_deposit.asset, fiat_deposit.amount, f'fiat deposit: {fiat_deposit.token}')
                fiat_deposit.balance_tx = ftx
                updated_records.append(payment_req)
                updated_records.append(fiat_deposit)
                updated_records.append(ftx)
                return updated_records
        # crown payments
        elif fiat_deposit.crown_payment:
            if not utils.is_email(crown_financial.EMAIL):
                logger.error('invalid crown_financial.EMAIL %s', crown_financial.EMAIL)
                return updated_records
            crown_payment = fiat_deposit.crown_payment
            tx = crown_financial.transaction_details(crown_payment.crown_txn_id)
            if tx.status == tx.STATUS_ACCEPTED:
                crown_payment.crown_status = tx.STATUS_ACCEPTED
                crown_payment.status = crown_payment.STATUS_COMPLETED
                fiat_deposit.status = fiat_deposit.STATUS_COMPLETED
                ftx_deposit = fiatdb_core.tx_create(fiat_deposit.user, FiatDbTransaction.ACTION_CREDIT, fiat_deposit.asset, fiat_deposit.amount, f'fiat deposit: {fiat_deposit.token}')
                fiat_deposit.balance_tx = ftx_deposit
                # check for autobuy asset in deposit code
                if fiat_deposit.deposit_code:
                    code = fiat_deposit.deposit_code
                    if code.autobuy_asset:
                        market = assets.assets_to_market(code.autobuy_asset, crown_financial.CURRENCY)
                        if market in assets.MARKETS:
                            # create broker order of 'autobuy_asset'
                            amount_dec = assets.asset_int_to_dec(fiat_deposit.asset, fiat_deposit.amount)
                            quote = dasset.bid_brute_force(market, amount_dec)
                            if quote.err != dasset.QuoteResult.OK:
                                logger.error('failed to make autobuy for deposit %s (QuoteResult: %s)', fiat_deposit.token, quote.err)
                                _fiat_deposit_autobuy_failure_email(fiat_deposit, code)
                            else:
                                err_msg, order = broker.order_validate(db_session, fiat_deposit.user, market, assets.MarketSide.BID, quote.amountBaseAsset)
                                if err_msg:
                                    logger.error('failed to make autobuy for deposit %s (%s)', fiat_deposit.token, err_msg)
                                    _fiat_deposit_autobuy_failure_email(fiat_deposit, code)
                                else:
                                    err_msg, ftx_order = broker.order_accept(db_session, order)
                                    if err_msg:
                                        logger.error('failed to make autobuy for deposit %s (%s)', fiat_deposit.token, err_msg)
                                        _fiat_deposit_autobuy_failure_email(fiat_deposit, code)
                                    else:
                                        updated_records.append(order)
                                        updated_records.append(ftx_order)
                                        websocket.broker_order_new_event(order)
                                        websocket.broker_order_update_event(order)
                updated_records.append(crown_payment)
                updated_records.append(fiat_deposit)
                updated_records.append(ftx_deposit)
                return updated_records
    # check expiry (for deposits via windcave)
    if fiat_deposit.status == fiat_deposit.STATUS_CREATED and fiat_deposit.windcave_payment_request:
        if datetime.now() > fiat_deposit.expiry:
            fiat_deposit.status = fiat_deposit.STATUS_CANCELLED
            updated_records.append(fiat_deposit)
            return updated_records
    return updated_records

def _fiat_deposit_email_msg(fiat_deposit: BalanceUpdate, msg: str):
    amount = assets.asset_int_to_dec(fiat_deposit.asset, fiat_deposit.amount)
    amount_str = assets.asset_dec_to_str(fiat_deposit.asset, amount)
    return f'Your deposit {fiat_deposit.token} ({amount_str} {fiat_deposit.asset}) is now {fiat_deposit.status}. \n\n{msg}'

def _fiat_deposit_email(fiat_deposit: BalanceUpdate):
    if fiat_deposit.status == fiat_deposit.STATUS_COMPLETED:
        email_utils.send_email('Deposit Completed', _fiat_deposit_email_msg(fiat_deposit, ''), fiat_deposit.user.email)
    if fiat_deposit.status == fiat_deposit.STATUS_CANCELLED:
        email_utils.send_email('Deposit Cancelled', _fiat_deposit_email_msg(fiat_deposit, ''), fiat_deposit.user.email)

def _crown_check_new_desposits(db_session: Session):
    if not utils.is_email(crown_financial.EMAIL):
        logger.error('invalid crown_financial.EMAIL %s', crown_financial.EMAIL)
        return
    txs = crown_financial.transactions_filtered_type(crown_financial.CrownTx.TYPE_DEPOSIT, datetime.now() - timedelta(days=7), datetime.now())
    for tx in txs:
        if tx.currency == crown_financial.CURRENCY and not CrownPayment.from_crown_txn_id(db_session, tx.crown_txn_id):
            payment = CrownPayment(utils.generate_key(), tx.currency, tx.amount, tx.crown_txn_id, tx.status)
            code = crown_financial.code_from_deposit(db_session, tx)
            if code:
                deposit = BalanceUpdate.fiat_deposit(code.user, crown_financial.CURRENCY, tx.amount, 0, crown_financial.CROWN_ACCOUNT_CODE)
                deposit.crown_payment = payment
                deposit.deposit_code = code
                db_session.add(payment)
                db_session.add(deposit)
                db_session.commit()

def _fiat_deposit_update_and_commit(db_session: Session, deposit: BalanceUpdate):
    if deposit.asset not in assets.ASSETS:
        logger.error('fiat deposit (%s) asset (%s) is not valid', deposit.token, deposit.asset)
        return
    while True:
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

def fiat_deposit_update(db_session: Session, token: str):
    with coordinator.lock:
        deposit = BalanceUpdate.from_token(db_session, token)
        if deposit:
            assert deposit.type == deposit.TYPE_DEPOSIT and not deposit.crypto
            _fiat_deposit_update_and_commit(db_session, deposit)

def fiat_deposits_update(db_session: Session):
    with coordinator.lock:
        deposits = BalanceUpdate.all_active(db_session, BalanceUpdate.TYPE_DEPOSIT, False)
        logger.info('num deposits: %d', len(deposits))
        for deposit in deposits:
            _fiat_deposit_update_and_commit(db_session, deposit)
        _crown_check_new_desposits(db_session)

def _fiat_withdrawal_update(fiat_withdrawal: BalanceUpdate):
    logger.info('processing fiat withdrawal %s (%s)..', fiat_withdrawal.token, fiat_withdrawal.status)
    updated_records: list = []
    # check withdrawals enabled
    if not tripwire.WITHDRAWAL.ok:
        return updated_records
    # check status
    if fiat_withdrawal.status == fiat_withdrawal.STATUS_CREATED:
        conf = fiat_withdrawal.withdrawal_confirmation
        if not conf:
            logger.error('fiat withdrawal (%s) does not have a confirmation record', fiat_withdrawal.token)
            return updated_records
        elif conf.confirmed is None:
            if conf.expired():
                ftx = withdrawal_cancel(fiat_withdrawal, 'confirmation expiry')  # sets status to STATUS_CANCELLED
                updated_records.append(fiat_withdrawal)
                updated_records.append(ftx)
        elif conf.confirmed:
            fiat_withdrawal.status = fiat_withdrawal.STATUS_AUTHORIZED
            updated_records.append(fiat_withdrawal)
        else:
            ftx = withdrawal_cancel(fiat_withdrawal, 'user')
            updated_records.append(fiat_withdrawal)
            updated_records.append(ftx)
        return updated_records
    if fiat_withdrawal.status == fiat_withdrawal.STATUS_AUTHORIZED:
        if not fiat_withdrawal.payout_request:
            assert fiat_withdrawal.withdrawal_confirmation
            address_book = fiat_withdrawal.withdrawal_confirmation.address_book
            assert address_book
            payout_request = payouts_core.payout_create(fiat_withdrawal.amount, crown_financial.CROWN_WITHDRAW_NAME, fiat_withdrawal.token, address_book)
            if not payout_request:
                logger.error('payouts_core.payout_create failed')
                return updated_records
            fiat_withdrawal.payout_request = payout_request
            updated_records.append(payout_request)
            fiat_withdrawal.status = fiat_withdrawal.STATUS_WITHDRAW
            updated_records.append(fiat_withdrawal)
            return updated_records
    if fiat_withdrawal.status == fiat_withdrawal.STATUS_WITHDRAW:
        if fiat_withdrawal.payout_request:
            payout_request = fiat_withdrawal.payout_request
            if payout_request.status == payout_request.STATUS_COMPLETED:
                fiat_withdrawal.status = fiat_withdrawal.STATUS_COMPLETED
                updated_records.append(fiat_withdrawal)
    return updated_records

def _fiat_withdrawal_email_msg(fiat_withdrawal: BalanceUpdate, msg: str):
    amount = assets.asset_int_to_dec(fiat_withdrawal.asset, fiat_withdrawal.amount)
    amount_str = assets.asset_dec_to_str(fiat_withdrawal.asset, amount)
    return f'Your withdrawal {fiat_withdrawal.token} ({amount_str} {fiat_withdrawal.asset}) is now {fiat_withdrawal.status}. \n\n{msg}'

def _fiat_withdrawal_email(fiat_withdrawal: BalanceUpdate):
    if fiat_withdrawal.status == fiat_withdrawal.STATUS_COMPLETED:
        email_utils.send_email('Withdrawal Completed', _fiat_withdrawal_email_msg(fiat_withdrawal, ''), fiat_withdrawal.user.email)

def _fiat_withdrawal_update_and_commit(db_session: Session, withdrawal: BalanceUpdate):
    if withdrawal.asset not in assets.ASSETS:
        logger.error('fiat withdrawal (%s) asset (%s) is not valid', withdrawal.token, withdrawal.asset)
        return
    # write a lock file for the withdrawal and refuse to process withdrawal if lock exists
    filename = f'fiat_withdrawal_{withdrawal.token}.lock'
    if not utils.lock_file_create(filename):
        msg = f'failed to create lockfile for withdrawal: {withdrawal.token}'
        logger.error(msg)
        email_utils.email_catastrophic_error(msg)
        return
    while True:
        updated_records = _fiat_withdrawal_update(withdrawal)
        # commit db if record updated
        if not updated_records:
            break
        for updated_record in updated_records:
            db_session.add(updated_record)
        db_session.commit()
        # send updates
        _fiat_withdrawal_email(withdrawal)
        websocket.fiat_withdrawal_update_event(withdrawal)
    # remove the lock file
    if not utils.lock_file_remove(filename):
        msg = f'failed to remove lockfile for withdrawal: {withdrawal.token}'
        logger.error(msg)
        email_utils.email_catastrophic_error(msg)

def fiat_withdrawal_update(db_session: Session, token: str):
    with coordinator.lock:
        if utils.lock_file_exists_any():
            logger.error('not processing withdrawals as lockfile directory not empty')
            return
        withdrawal = BalanceUpdate.from_token(db_session, token)
        if withdrawal:
            assert withdrawal.type == withdrawal.TYPE_WITHDRAWAL and not withdrawal.crypto
            _fiat_withdrawal_update_and_commit(db_session, withdrawal)

def fiat_withdrawals_update(db_session: Session):
    with coordinator.lock:
        if utils.lock_file_exists_any():
            logger.error('not processing withdrawals as lockfile directory not empty')
            return
        withdrawals = BalanceUpdate.all_active(db_session, BalanceUpdate.TYPE_WITHDRAWAL, False)
        logger.info('num fiat withdrawals: %d', len(withdrawals))
        for withdrawal in withdrawals:
            _fiat_withdrawal_update_and_commit(db_session, withdrawal)

def _crypto_deposit_email_msg(deposit: BalanceUpdate, verb: str, msg: str):
    amount = assets.asset_int_to_dec(deposit.asset, deposit.amount)
    amount_str = assets.asset_dec_to_str(deposit.asset, amount)
    deposit_id = deposit.txid if deposit.txid else deposit.wallet_reference
    if deposit_id:
        deposit_id = utils.shorten(deposit_id)
    return f'Your deposit {deposit_id} ({amount_str} {deposit.asset}) is now {verb}. \n\n{msg}'

def _crypto_deposit_email(deposit: BalanceUpdate):
    if deposit.status == deposit.STATUS_COMPLETED:
        email_utils.send_email('Deposit Confirmed', _crypto_deposit_email_msg(deposit, 'confirmed', ''), deposit.user.email)
    elif deposit.status == deposit.STATUS_CREATED:
        email_utils.send_email('Deposit Incoming', _crypto_deposit_email_msg(deposit, 'incoming', ''), deposit.user.email)

def _crypto_deposits_wallet_check(db_session: Session, new_crypto_deposits: list[BalanceUpdate], updated_crypto_deposits: list[BalanceUpdate], user: User, asset: str, addr_list: list[str]):
    for addr in addr_list:
        wallet_deposits = wallet.address_deposits(asset, None, addr)
        for wallet_deposit in wallet_deposits:
            completed = wallet.deposit_completed(asset, None, wallet_deposit.txid)
            crypto_deposit = BalanceUpdate.from_txid(db_session, wallet_deposit.txid)
            if not crypto_deposit:
                crypto_deposit = BalanceUpdate.crypto_deposit(user, asset, None, wallet_deposit.amount_deposited(), 0, addr)
                crypto_deposit.txid = wallet_deposit.txid  # pyright: ignore [reportGeneralTypeIssues]  WTF pyright??
                crypto_deposit.wallet_reference = wallet_deposit.txid  # pyright: ignore [reportGeneralTypeIssues]  WTF pyright??
                if completed:
                    crypto_deposit.status = BalanceUpdate.STATUS_COMPLETED
                new_crypto_deposits.append(crypto_deposit)
            if (crypto_deposit in new_crypto_deposits or crypto_deposit.status != crypto_deposit.STATUS_COMPLETED) and completed:
                # credit the users account
                ftx = fiatdb_core.tx_create(user, FiatDbTransaction.ACTION_CREDIT, asset, wallet_deposit.amount_deposited(), f'crypto deposit: {crypto_deposit.token}')
                db_session.add(ftx)
                # update crypto deposit
                crypto_deposit.status = crypto_deposit.STATUS_COMPLETED
                crypto_deposit.balance_tx = ftx
                updated_crypto_deposits.append(crypto_deposit)
            if not crypto_deposit.crypto_address:
                addr_db = CryptoAddress.from_addr(db_session, addr)
                if addr_db:
                    crypto_deposit.crypto_address = addr_db
            db_session.add(crypto_deposit)
            db_session.commit()

def _crypto_deposits_dasset_check(db_session: Session, new_crypto_deposits: list[BalanceUpdate], updated_crypto_deposits: list[BalanceUpdate], user: User, asset: str):
    if asset not in assets.ASSETS:
        logger.error('dasset crypto deposit asset (%s) is not valid', asset)
        return
    if not user.dasset_subaccount:
        logger.error('user %s dasset subaccount does not exist', user.email)
        return
    dasset_deposits = dasset.crypto_deposits(asset, user.dasset_subaccount.subaccount_id)
    for dasset_deposit in dasset_deposits:
        completed = dasset.crypto_deposit_completed(dasset_deposit)
        crypto_deposit = BalanceUpdate.from_txid(db_session, dasset_deposit.txid)
        if not crypto_deposit:
            amount_int = assets.asset_dec_to_int(asset, dasset_deposit.amount)
            crypto_deposit = BalanceUpdate.crypto_deposit(user, asset, None, amount_int, 0, dasset_deposit.address)
            crypto_deposit.exchange_reference = dasset_deposit.id
            crypto_deposit.txid = dasset_deposit.txid  # pyright: ignore [reportGeneralTypeIssues]  WTF pyright??
            if completed:
                crypto_deposit.status = crypto_deposit.STATUS_COMPLETED
            new_crypto_deposits.append(crypto_deposit)
        if (crypto_deposit in new_crypto_deposits or crypto_deposit.status != crypto_deposit.STATUS_COMPLETED) and completed:
            # if deposit now completed transfer the funds to the master account
            if not dasset.transfer(None, user.dasset_subaccount.subaccount_id, asset, dasset_deposit.amount):
                logger.error('failed to transfer funds from subaccount to master %s', dasset_deposit.id)
                continue
            # and credit the users account
            ftx = fiatdb_core.tx_create(user, FiatDbTransaction.ACTION_CREDIT, asset, crypto_deposit.amount, f'crypto deposit: {crypto_deposit.token}')
            db_session.add(ftx)
            # update crypto deposit
            crypto_deposit.status = crypto_deposit.STATUS_COMPLETED
            crypto_deposit.balance_tx = ftx
            updated_crypto_deposits.append(crypto_deposit)
        if not crypto_deposit.crypto_address:
            addr = CryptoAddress.from_addr(db_session, dasset_deposit.address)
            if addr:
                crypto_deposit.crypto_address = addr
        db_session.add(crypto_deposit)
        db_session.commit()

def _crypto_deposits_address_check(db_session: Session, new_crypto_deposits: list[BalanceUpdate], updated_crypto_deposits: list[BalanceUpdate]):
    # query for list of addresses that need to be checked
    addrs = CryptoAddress.need_to_be_checked(db_session)
    # sort in groups of assets for each user
    user_assets: Dict[str, Tuple[User, dict]] = {}
    for addr in addrs:
        if addr.user.email not in user_assets:
            user_assets[addr.user.email] = addr.user, {}
        _, asset_dict = user_assets[addr.user.email]
        if addr.asset not in asset_dict:
            asset_dict[addr.asset] = [addr.address]
        # update checked at time of CryptoAddress
        addr.checked_at = int(datetime.timestamp(datetime.now()))
        db_session.add(addr)
    db_session.commit()
    # check for new deposits, update existing deposits
    for user, asset_dict in user_assets.values():
        for asset, addr_list in asset_dict.items():
            if wallet.deposits_supported(asset, None):
                _crypto_deposits_wallet_check(db_session, new_crypto_deposits, updated_crypto_deposits, user, asset, addr_list)
            else:
                _crypto_deposits_dasset_check(db_session, new_crypto_deposits, updated_crypto_deposits, user, asset)

def _crypto_deposits_updated_wallet_check(db_session: Session, updated_crypto_deposits: list[BalanceUpdate]):
    for deposit in BalanceUpdate.active_deposit_of_wallet(db_session):
        logger.info('processing crypto deposit %s (status: %s)..', deposit.token, deposit.status)
        if wallet.deposit_expired(deposit.asset, deposit.l2_network, deposit.wallet_reference):
            deposit.status = deposit.STATUS_CANCELLED
            updated_crypto_deposits.append(deposit)
        elif wallet.deposit_completed(deposit.asset, deposit.l2_network, deposit.wallet_reference):
            deposit.status = deposit.STATUS_COMPLETED
            # credit the users account
            ftx = fiatdb_core.tx_create(deposit.user, FiatDbTransaction.ACTION_CREDIT, deposit.asset, deposit.amount, f'crypto deposit: {deposit.token}')
            deposit.balance_tx = ftx
            db_session.add(ftx)
            updated_crypto_deposits.append(deposit)
        db_session.add(deposit)
        db_session.commit()

def crypto_wallet_deposits_check(db_session: Session):
    updated_crypto_deposits: list[BalanceUpdate] = []
    with coordinator.lock:
        # check crypto deposits in our wallet
        _crypto_deposits_updated_wallet_check(db_session, updated_crypto_deposits)
    # send updates
    for deposit in updated_crypto_deposits:
        _crypto_deposit_email(deposit)
        websocket.crypto_deposit_update_event(deposit)

def crypto_deposits_check(db_session: Session):
    new_crypto_deposits: list[BalanceUpdate] = []
    updated_crypto_deposits: list[BalanceUpdate] = []
    with coordinator.lock:
        # check crypto deposits from addresses that are due to be checked (from dasset or our wallet)
        _crypto_deposits_address_check(db_session, new_crypto_deposits, updated_crypto_deposits)
        # check crypto deposits in our wallet
        _crypto_deposits_updated_wallet_check(db_session, updated_crypto_deposits)
    # send updates
    for deposit in new_crypto_deposits:
        _crypto_deposit_email(deposit)
        websocket.crypto_deposit_new_event(deposit)
    for deposit in updated_crypto_deposits:
        _crypto_deposit_email(deposit)
        websocket.crypto_deposit_update_event(deposit)

def _crypto_withdrawal_update(crypto_withdrawal: BalanceUpdate):
    logger.info('processing crypto withdrawal %s (%s)..', crypto_withdrawal.token, crypto_withdrawal.status)
    updated_records: list[BalanceUpdate] = []
    # check withdrawals enabled
    if not tripwire.WITHDRAWAL.ok:
        return updated_records
    # check status
    if crypto_withdrawal.status == crypto_withdrawal.STATUS_CREATED:
        conf: WithdrawalConfirmation = crypto_withdrawal.withdrawal_confirmation
        if not conf:
            logger.error('crypto withdrawal (%s) does not have a confirmation record', crypto_withdrawal.token)
        elif conf.confirmed is None:
            if conf.expired():
                ftx = withdrawal_cancel(crypto_withdrawal, 'confirmation expiry')  # sets status to STATUS_CANCELLED
                updated_records.append(crypto_withdrawal)
                updated_records.append(ftx)
        elif conf.confirmed:
            crypto_withdrawal.status = crypto_withdrawal.STATUS_AUTHORIZED
            updated_records.append(crypto_withdrawal)
        else:
            ftx = withdrawal_cancel(crypto_withdrawal, 'user')
            updated_records.append(crypto_withdrawal)
            updated_records.append(ftx)
        return updated_records
    if crypto_withdrawal.status == crypto_withdrawal.STATUS_AUTHORIZED:

        # we process btc onchain withdrawals as a batch so skip this
        if crypto_withdrawal.asset == assets.BTC.symbol and crypto_withdrawal.l2_network is None:
            logger.info('authorized BTC onchain withdrawals will be done in the batch process')
            return updated_records

        if not crypto_withdrawal.wallet_reference and not crypto_withdrawal.exchange_reference:
            asset = crypto_withdrawal.asset
            l2_network = crypto_withdrawal.l2_network
            amount_dec = assets.asset_int_to_dec(asset, crypto_withdrawal.amount)
            recipient = crypto_withdrawal.recipient
            # create wallet/exchange withdrawal
            exchange_reference = None
            wallet_reference = None
            if wallet.withdrawals_supported(asset, l2_network):
                # check if recipient expired
                if (wallet.recipient_expired(asset, l2_network, recipient)):
                    crypto_withdrawal.status = crypto_withdrawal.STATUS_CANCELLED
                    updated_records.append(crypto_withdrawal)
                    logger.error('withdrawal recipient has expired')
                    return updated_records
                # check funds are available and make withdrawal
                logger.info('check local wallet has funds available')
                if not wallet.funds_available(asset, l2_network, amount_dec):
                    logger.error('wallet.funds_available failed')
                    return updated_records
                logger.info('create local wallet withdrawal')
                wallet_reference, err_msg = wallet.withdrawal_create(asset, l2_network, amount_dec, recipient)
                if err_msg:
                    logger.error('wallet.withdrawal_create failed - %s', err_msg)
                    return updated_records
            else:
                if not dasset.funds_available_us(asset, amount_dec):
                    logger.error('dasset.funds_available_us failed')
                    return updated_records
                exchange_reference = dasset.crypto_withdrawal_create(asset, amount_dec, recipient)
                if not exchange_reference:
                    logger.error('dasset.crypto_withdrawal_create failed')
                    return updated_records
            if wallet_reference:
                crypto_withdrawal.wallet_reference = wallet_reference
            if exchange_reference:
                crypto_withdrawal.exchange_reference = exchange_reference  # pyright: ignore [reportGeneralTypeIssues]  WTF pyright??
        crypto_withdrawal.status = crypto_withdrawal.STATUS_WITHDRAW
        updated_records.append(crypto_withdrawal)
        return updated_records
    if crypto_withdrawal.status == crypto_withdrawal.STATUS_WITHDRAW:
        if crypto_withdrawal.wallet_reference:
            # check wallet withdrawal
            if wallet.withdrawal_completed(crypto_withdrawal.asset, crypto_withdrawal.l2_network, crypto_withdrawal.wallet_reference):
                crypto_withdrawal.status = crypto_withdrawal.STATUS_COMPLETED
                updated_records.append(crypto_withdrawal)
        elif crypto_withdrawal.exchange_reference:
            # check exchange withdrawal
            status = dasset.crypto_withdrawal_status_check(crypto_withdrawal.exchange_reference)
            if status == dasset.CRYPTO_WITHDRAWAL_STATUS_COMPLETED:
                crypto_withdrawal.status = crypto_withdrawal.STATUS_COMPLETED
                updated_records.append(crypto_withdrawal)
            elif status == dasset.CRYPTO_WITHDRAWAL_STATUS_2FA:
                if not dasset.crypto_withdrawal_confirm(crypto_withdrawal.exchange_reference):
                    logger.error('failed to confirm crypto withdrawal %s', crypto_withdrawal.token)
            elif status == dasset.CRYPTO_WITHDRAWAL_STATUS_UNKNOWN:
                logger.error('failed to get crypto withdrawal %s status', crypto_withdrawal.token)
        return updated_records
    return updated_records

def _crypto_withdrawal_email_msg(crypto_withdrawal: BalanceUpdate, msg: str):
    amount = assets.asset_int_to_dec(crypto_withdrawal.asset, crypto_withdrawal.amount)
    amount_str = assets.asset_dec_to_str(crypto_withdrawal.asset, amount)
    return f'Your withdrawal {crypto_withdrawal.token} ({amount_str} {crypto_withdrawal.asset}) is now {crypto_withdrawal.status}. \n\n{msg}'

def _crypto_withdrawal_email(crypto_withdrawal: BalanceUpdate):
    if crypto_withdrawal.status == crypto_withdrawal.STATUS_COMPLETED:
        email_utils.send_email('Withdrawal Completed', _crypto_withdrawal_email_msg(crypto_withdrawal, ''), crypto_withdrawal.user.email)

def _crypto_withdrawal_update_and_commit(db_session: Session, withdrawal: BalanceUpdate):
    if withdrawal.asset not in assets.ASSETS:
        logger.error('crypto withdrawal (%s) asset (%s) is not valid', withdrawal.token, withdrawal.asset)
        return
    # write a lock file for the withdrawal and refuse to process withdrawal if lock exists
    filename = f'crypto_withdrawal_{withdrawal.token}.lock'
    if not utils.lock_file_create(filename):
        msg = f'failed to create lockfile for withdrawal: {withdrawal.token}'
        logger.error(msg)
        email_utils.email_catastrophic_error(msg)
        return
    # process withdrawal
    while True:
        updated_records = _crypto_withdrawal_update(withdrawal)
        # commit db if records updated
        if not updated_records:
            break
        for rec in updated_records:
            db_session.add(rec)
        db_session.commit()
        # send updates
        _crypto_withdrawal_email(withdrawal)
        websocket.crypto_withdrawal_update_event(withdrawal)
    # remove the lock file
    if not utils.lock_file_remove(filename):
        msg = f'failed to remove lockfile for withdrawal: {withdrawal.token}'
        logger.error(msg)
        email_utils.email_catastrophic_error(msg)

def crypto_withdrawal_update(db_session: Session, token: str):
    with coordinator.lock:
        if utils.lock_file_exists_any():
            logger.error('not processing withdrawals as lockfile directory not empty')
            return
        withdrawal = BalanceUpdate.from_token(db_session, token)
        if withdrawal:
            assert withdrawal.type == withdrawal.TYPE_WITHDRAWAL and withdrawal.crypto
            _crypto_withdrawal_update_and_commit(db_session, withdrawal)

def btc_onchain_withdrawals_update(db_session: Session):
    assert wallet.withdrawals_supported(assets.BTC.symbol, None)
    with coordinator.lock:
        if utils.lock_file_exists_any():
            logger.error('not processing withdrawals as lockfile directory not empty')
            return
        # get authorized btc on chain withdrawals
        withdrawals = BalanceUpdate.all_of_state_and_asset(db_session, BalanceUpdate.TYPE_WITHDRAWAL, BalanceUpdate.STATUS_AUTHORIZED, assets.BTC.symbol, None)
        logger.info('num btc onchain withdrawals authorized: %d', len(withdrawals))
        # create signed psbt
        addrs = []
        amounts_int = []
        amount_total_int = 0
        for withdrawal in withdrawals:
            addrs.append(withdrawal.recipient)
            amounts_int.append(withdrawal.amount)
            amount_total_int += withdrawal.amount
        available = wallet.btc_onchain_funds(included_unconfirmed=True)
        available -= 10000  # allow for large transaction fee
        if available < amount_total_int:
            logger.error('btc_onchain_funds (%d sats) is not enough for withdrawal total (%d)', available, amount_total_int)
            return
        txid, signed_psbt, err = wallet.btc_signed_psbt_create(addrs, amounts_int, minconf=0)
        if err:
            logger.error(err)
            return
        assert txid and signed_psbt
        # commit updated state of withdrawals in DB
        for withdrawal in withdrawals:
            withdrawal.wallet_reference = txid
            withdrawal.txid = txid
            withdrawal.status = withdrawal.STATUS_WITHDRAW
            db_session.add(withdrawal)
        db_session.commit()
        # broadcast btc tx
        if not wallet.btc_signed_psbt_broadcast(signed_psbt):
            msg = f'failed to broadcast signed psbt: txid = {txid}'
            logger.error(msg)
            email_utils.email_catastrophic_error(msg)
            return
        # send updates
        for withdrawal in withdrawals:
            _crypto_withdrawal_email(withdrawal)
            websocket.crypto_withdrawal_update_event(withdrawal)

def crypto_withdrawals_update(db_session: Session):
    with coordinator.lock:
        if utils.lock_file_exists_any():
            logger.error('not processing withdrawals as lockfile directory not empty')
            return
        withdrawals = BalanceUpdate.all_active(db_session, BalanceUpdate.TYPE_WITHDRAWAL, True)
        logger.info('num crypto withdrawals: %d', len(withdrawals))
        for withdrawal in withdrawals:
            _crypto_withdrawal_update_and_commit(db_session, withdrawal)
