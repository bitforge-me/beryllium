import datetime
import logging

import fiatdb_core
import dasset
import assets
from assets import asset_is_crypto, asset_is_fiat, MarketSide
from models import BrokerOrder, ExchangeOrder, DassetSubaccount, FiatDbTransaction
import websocket
import email_utils
import web_utils
import coordinator

logger = logging.getLogger(__name__)

#
# Helper functions (public)
#

def user_subaccount_get_or_create(db_session, user):
    # create subaccount for user
    if not user.dasset_subaccount:
        subaccount_id = dasset.subaccount_create(user.token)
        if not subaccount_id:
            logger.error('failed to create subaccount for %s', user.email)
            return None
        subaccount = DassetSubaccount(user, subaccount_id)
        db_session.add(subaccount)
        return subaccount
    return user.dasset_subaccount

def order_check_funds(db_session, user, asset, amount_dec):
    if asset_is_crypto(asset):
        # get subaccount for user
        subaccount = user_subaccount_get_or_create(db_session, user)
        if not subaccount:
            return web_utils.FAILED_EXCHANGE
        subaccount_id = subaccount.subaccount_id
        if not dasset.funds_available_user(asset, amount_dec, subaccount_id):
            return web_utils.INSUFFICIENT_BALANCE
    else:
        # check fiat funds on dasset
        if not dasset.funds_available_us(asset, amount_dec):
            return web_utils.INSUFFICIENT_LIQUIDITY
        # and fiat funds user has with us
        balance = fiatdb_core.user_balance(db_session, asset, user)
        balance_dec = assets.asset_int_to_dec(asset, balance)
        if balance_dec < amount_dec:
            return web_utils.INSUFFICIENT_BALANCE
    return None

#
# Helper functions (private)
#

# pylint: disable=too-many-statements
def _broker_order_action(db_session, broker_order):
    logger.info('processing broker order %s (%s)..', broker_order.token, broker_order.status)
    updated_records = []
    base_amount_dec = assets.asset_int_to_dec(broker_order.base_asset, broker_order.base_amount)
    quote_amount_dec = assets.asset_int_to_dec(broker_order.quote_asset, broker_order.quote_amount)
    price = quote_amount_dec / base_amount_dec
    side = MarketSide.parse(broker_order.side)
    # check side
    if not side:
        logger.error('invalid side "%s" for broker order %s', broker_order.side, broker_order.token)
        broker_order.status = broker_order.STATUS_FAILED
        updated_records.append(broker_order)
        return updated_records
    # check balance
    if broker_order.status == broker_order.STATUS_READY:
        err_msg = order_check_funds(db_session, broker_order.user, broker_order.quote_asset, quote_amount_dec)
        if err_msg:
            logger.error('"%s" for broker order %s', err_msg, broker_order.token)
            broker_order.status = broker_order.STATUS_FAILED
            updated_records.append(broker_order)
            return updated_records
        if side is MarketSide.BID and asset_is_fiat(broker_order.quote_asset):
            asset = broker_order.quote_asset
            amount_int = broker_order.quote_amount
            ftx = fiatdb_core.tx_create(db_session, broker_order.user, FiatDbTransaction.ACTION_DEBIT, asset, amount_int, f'broker order: {broker_order.token}')
            if not ftx:
                logger.error('failed to create fiatdb transaction for broker order %s', broker_order.token)
                broker_order.status = broker_order.STATUS_FAILED
                updated_records.append(broker_order)
                return updated_records
            updated_records.append(ftx)
        broker_order.status = broker_order.STATUS_FIAT_DEBITED
        updated_records.append(broker_order)
        return updated_records
    # create exchange order
    if broker_order.status == broker_order.STATUS_FIAT_DEBITED:
        exchange_order_id = dasset.order_create(broker_order.market, side, base_amount_dec, price)
        if not exchange_order_id:
            msg = f'{broker_order.token}, {broker_order.market}, {broker_order.side}, {broker_order.base_amount}'
            logger.error('failed to create exchange order - %s', msg)
            email_utils.send_email(logger, 'failed to create exchange order', msg)
            return updated_records
        exchange_order = ExchangeOrder(exchange_order_id)
        broker_order.exchange_order = exchange_order
        broker_order.status = broker_order.STATUS_EXCHANGE
        updated_records.append(exchange_order)
        updated_records.append(broker_order)
        return updated_records
    # finalize
    if broker_order.status == broker_order.STATUS_EXCHANGE:
        # check exchange order
        if dasset.order_status_check(broker_order.exchange_order.exchange_reference, broker_order.market):
            if side is MarketSide.ASK and asset_is_fiat(broker_order.quote_asset):
                asset = broker_order.quote_asset
                amount_int = broker_order.quote_amount
                ftx = fiatdb_core.tx_create(db_session, broker_order.user, FiatDbTransaction.ACTION_CREDIT, asset, amount_int, f'broker order: {broker_order.token}')
                if not ftx:
                    logger.error('failed to create fiatdb transaction for broker order %s', broker_order.token)
                    return updated_records
                updated_records.append(ftx)
            broker_order.status = broker_order.STATUS_COMPLETED
            updated_records.append(broker_order)
        else:
            msg = f'{broker_order.token}, {broker_order.exchange_order.exchange_reference}'
            logger.error('failed to complete exchange order - %s', msg)
            email_utils.send_email(logger, 'failed to complete exchange order', msg)
        return updated_records
    # check expiry
    if broker_order.status in [broker_order.STATUS_CREATED, broker_order.STATUS_READY]:
        if datetime.datetime.now() > broker_order.expiry:
            broker_order.status = broker_order.STATUS_EXPIRED
            updated_records.append(broker_order)
            return updated_records
    return updated_records

def _email_msg(broker_order, msg):
    side = assets.market_side_nice(broker_order.side)
    amount =  assets.asset_int_to_dec(broker_order.base_asset, broker_order.base_amount)
    amount = assets.asset_dec_to_str(broker_order.base_asset, amount)
    return f'Your order {broker_order.token} ({side} {amount} {broker_order.base_asset}) is now {broker_order.status}. \n\n{msg}'

def _broker_order_email(broker_order):
    if broker_order.status == broker_order.STATUS_FAILED:
        email_utils.send_email(logger, 'Order Failed', _email_msg(broker_order, ''), broker_order.user.email)
    if broker_order.status == broker_order.STATUS_COMPLETED:
        email_utils.send_email(logger, 'Order Completed', _email_msg(broker_order, ''), broker_order.user.email)
    if broker_order.status == broker_order.STATUS_EXPIRED:
        email_utils.send_email(logger, 'Order Expired', _email_msg(broker_order, ''), broker_order.user.email)

#
# Public functions
#

def broker_order_update_and_commit(db_session, broker_order):
    while True:
        with coordinator.lock:
            updated_records = _broker_order_action(db_session, broker_order)
            # commit db if records updated
            if not updated_records:
                return
            for rec in updated_records:
                db_session.add(rec)
            db_session.commit()
            # send updates
            _broker_order_email(broker_order)
            websocket.broker_order_update_event(broker_order)

def broker_orders_update(db_session):
    orders = BrokerOrder.all_active(db_session)
    logger.info('num orders: %d', len(orders))
    for broker_order in orders:
        broker_order_update_and_commit(db_session, broker_order)
