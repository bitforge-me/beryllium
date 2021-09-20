import datetime
import logging

import payments_core
import dasset
from dasset import market_side_is, MarketSide
from models import ExchangeDeposit, ExchangeOrder, ExchangeWithdrawal
import websocket
import utils

logger = logging.getLogger(__name__)

# pylint: disable=too-many-statements
def _broker_order_buy_crypto_with_fiat_update(broker_order):
    logger.info('processing broker order %s (%s)..', broker_order.token, broker_order.status)
    updated_records = []
    # check payment
    if broker_order.status == broker_order.STATUS_READY:
        if broker_order.windcave_payment_request:
            payment_req = broker_order.windcave_payment_request
            payments_core.payment_request_status_update(payment_req)
            if payment_req.status == payment_req.STATUS_CANCELLED:
                broker_order.status = broker_order.STATUS_CANCELLED
                updated_records.append(payment_req)
                updated_records.append(broker_order)
                return updated_records
            if payment_req.status == payment_req.STATUS_COMPLETED:
                broker_order.status = broker_order.STATUS_CONFIRMED
                updated_records.append(payment_req)
                updated_records.append(broker_order)
                return updated_records
    # create exchange order
    if broker_order.status == broker_order.STATUS_CONFIRMED:
        base_amount_dec = dasset.asset_int_to_dec(broker_order.base_asset, broker_order.base_amount)
        quote_amount_dec = dasset.asset_int_to_dec(broker_order.quote_asset, broker_order.quote_amount)
        amount_total = base_amount_dec + dasset.asset_withdraw_fee(broker_order.base_asset)
        price = quote_amount_dec / amount_total
        exchange_order_id = dasset.order_create_req(broker_order.market, MarketSide.BID, amount_total, price)
        if not exchange_order_id:
            msg = f'{broker_order.token}, {broker_order.market}, {broker_order.side}, {broker_order.base_amount}'
            logger.error('failed to create exchange order - %s', msg)
            utils.send_email(logger, 'failed to create exchange order', msg)
            return updated_records
        exchange_order = ExchangeOrder(exchange_order_id)
        broker_order.exchange_order = exchange_order
        broker_order.status = broker_order.STATUS_EXCHANGE
        updated_records.append(exchange_order)
        updated_records.append(broker_order)
        return updated_records
    # create withdrawal
    if broker_order.status == broker_order.STATUS_EXCHANGE:
        # check exchange order
        if dasset.order_status_check(broker_order.exchange_order.exchange_reference, broker_order.market):
            # create exchange withdrawal
            base_amount_dec = dasset.asset_int_to_dec(broker_order.base_asset, broker_order.base_amount)
            exchange_withdrawal_id = dasset.crypto_withdrawal_create_req(broker_order.base_asset, base_amount_dec, broker_order.recipient)
            if not exchange_withdrawal_id:
                msg = f'{broker_order.token}, {broker_order.base_asset}, {broker_order.base_amount}'
                logger.error('failed to create exchange withdrawal - %s', msg)
                utils.send_email(logger, 'failed to create exchange withdrawal', msg)
                return updated_records
            exchange_withdrawal = ExchangeWithdrawal(exchange_withdrawal_id)
            broker_order.exchange_withdrawal = exchange_withdrawal
            broker_order.status = broker_order.STATUS_WITHDRAW
            updated_records.append(exchange_withdrawal)
            updated_records.append(broker_order)
        else:
            msg = f'{broker_order.token}, {broker_order.exchange_order.exchange_reference}'
            logger.error('failed to complete exchange order - %s', msg)
            utils.send_email(logger, 'failed to complete exchange order', msg)
        return updated_records
    # check withdrawal
    if broker_order.status == broker_order.STATUS_WITHDRAW:
        # check exchange withdrawal
        if dasset.crypto_withdrawal_status_check(broker_order.exchange_withdrawal.exchange_reference):
            broker_order.status = broker_order.STATUS_COMPLETED
            updated_records.append(broker_order)
        return updated_records
    # check expiry
    if broker_order.status in [broker_order.STATUS_CREATED, broker_order.STATUS_READY]:
        if datetime.datetime.now() > broker_order.expiry:
            broker_order.status = broker_order.STATUS_EXPIRED
            updated_records.append(broker_order)
            return updated_records
    return updated_records

def _new_deposit(db_session, deposits):
    for dep in deposits:
        if not ExchangeDeposit.from_txid(db_session, dep.txid):
            return dep
    return None

def _broker_order_sell_crypto_for_fiat_update(db_session, broker_order):
    logger.info('processing broker order %s (%s)..', broker_order.token, broker_order.status)
    updated_records = []
    # check deposit
    if broker_order.status == broker_order.STATUS_READY:
        amount = dasset.asset_int_to_dec(broker_order.quote_asset, broker_order.quote_amount)
        deposits = dasset.crypto_deposit_search(broker_order.quote_asset, broker_order.address, amount, broker_order.user.dasset_subaccount.subaccount_id)
        new_deposit = _new_deposit(db_session, deposits)
        if not new_deposit:
            return updated_records
        exchange_deposit = ExchangeDeposit(new_deposit.id, new_deposit.txid)
        broker_order.exchange_deposit = exchange_deposit
        broker_order.status = broker_order.STATUS_INCOMING
        updated_records.append(exchange_deposit)
        updated_records.append(broker_order)
        return updated_records
    if broker_order.status == broker_order.STATUS_INCOMING:
        if dasset.crypto_deposit_status_check(broker_order.exchange_deposit.exchange_reference):
            broker_order.status = broker_order.STATUS_CONFIRMED
            updated_records.append(broker_order)
        return updated_records
    # exchange order
    if broker_order.status == broker_order.STATUS_CONFIRMED:
        base_amount_dec = dasset.asset_int_to_dec(broker_order.base_asset, broker_order.base_amount)
        quote_amount_dec = dasset.asset_int_to_dec(broker_order.quote_asset, broker_order.quote_amount)
        amount_total = base_amount_dec
        price = quote_amount_dec / amount_total
        exchange_order_id = dasset.order_create_req(broker_order.market, MarketSide.ASK, amount_total, price)
        if not exchange_order_id:
            msg = f'{broker_order.token}, {broker_order.market}, {broker_order.side}, {broker_order.base_amount}'
            logger.error('failed to create exchange order - %s', msg)
            utils.send_email(logger, 'failed to create exchange order', msg)
            return updated_records
        exchange_order = ExchangeOrder(exchange_order_id)
        broker_order.exchange_order = exchange_order
        broker_order.status = broker_order.STATUS_EXCHANGE
        updated_records.append(exchange_order)
        updated_records.append(broker_order)
        return updated_records
    # create payout
    if broker_order.status == broker_order.STATUS_EXCHANGE:
        # check exchange order
        if dasset.order_status_check(broker_order.exchange_order.exchange_reference, broker_order.market):
            # create payout
            quote_amount_dec = dasset.asset_int_to_dec(broker_order.quote_asset, broker_order.quote_amount)
            payout_req = payments_core.payout_create(broker_order.quote_amount, broker_order.token, '', broker_order.user.email, broker_order.recipient, broker_order.token, '', '')
            broker_order.payout_request = payout_req
            broker_order.status = broker_order.STATUS_WITHDRAW
            updated_records.append(payout_req)
            updated_records.append(broker_order)
        else:
            msg = f'{broker_order.token}, {broker_order.exchange_order.exchange_reference}'
            logger.error('failed to complete exchange order - %s', msg)
            utils.send_email(logger, 'failed to complete exchange order', msg)
        return updated_records
    # check payout
    if broker_order.status == broker_order.STATUS_WITHDRAW:
        payout_req = broker_order.payout_request
        if not payout_req:
            msg = f'{broker_order.token}'
            logger.error('failed to find payout for broker order - %s', msg)
            utils.send_email(logger, 'failed to find payout for broker order', msg)
            return updated_records
        # check payout status
        if payout_req.status == payout_req.STATUS_COMPLETED:
            broker_order.status = broker_order.STATUS_COMPLETED
            updated_records.append(broker_order)
        return updated_records
    # check expiry
    if broker_order.status in [broker_order.STATUS_CREATED, broker_order.STATUS_READY]:
        if datetime.datetime.now() > broker_order.expiry:
            broker_order.status = broker_order.STATUS_EXPIRED
            updated_records.append(broker_order)
            return updated_records
    return updated_records

def _email_msg(broker_order, msg):
    side = dasset.market_side_nice(broker_order.side)
    amount =  dasset.asset_int_to_dec(broker_order.base_asset, broker_order.base_amount)
    amount = dasset.asset_dec_to_str(broker_order.base_asset, amount)
    return f'Your order {broker_order.token} ({side} {amount} {broker_order.base_asset}) is now {broker_order.status}. \n\n{msg}'

def _broker_order_email(broker_order):
    if broker_order.status == broker_order.STATUS_CONFIRMED:
        utils.send_email(logger, 'Order Confirmed', _email_msg(broker_order, 'The exchange will now be made.'), broker_order.user.email)
    if broker_order.status == broker_order.STATUS_WITHDRAW:
        utils.send_email(logger, 'Order Withdrawing', _email_msg(broker_order, ''), broker_order.user.email)
    if broker_order.status == broker_order.STATUS_COMPLETED:
        utils.send_email(logger, 'Order Completed', _email_msg(broker_order, ''), broker_order.user.email)
    if broker_order.status == broker_order.STATUS_EXPIRED:
        utils.send_email(logger, 'Order Expired', _email_msg(broker_order, ''), broker_order.user.email)

def broker_order_update_and_commit(db_session, broker_order):
    while True:
        updated_records = []
        # process crypto buy with fiat
        if market_side_is(broker_order.side, MarketSide.BID):
            if dasset.asset_is_crypto(broker_order.base_asset) and not dasset.asset_is_crypto(broker_order.quote_asset):
                updated_records = _broker_order_buy_crypto_with_fiat_update(broker_order)
        # process crypto sell for fiat
        if market_side_is(broker_order.side, MarketSide.ASK):
            if dasset.asset_is_crypto(broker_order.base_asset) and not dasset.asset_is_crypto(broker_order.quote_asset):
                updated_records = _broker_order_sell_crypto_for_fiat_update(db_session, broker_order)
        # commit db if records updated
        if not updated_records:
            return
        for rec in updated_records:
            db_session.add(rec)
        db_session.commit()
        # send updates
        _broker_order_email(broker_order)
        websocket.broker_order_update_event(broker_order)
