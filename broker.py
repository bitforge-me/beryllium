import datetime
import logging

import payments_core
import dasset
from models import ExchangeOrder, ExchangeWithdrawal

logger = logging.getLogger(__name__)

def _broker_order_update(broker_order):
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
        price = broker_order.quote_amount / broker_order.base_amount
        exchange_order_id = dasset.order_create_req(broker_order.market, dasset.MarketSide.BID, broker_order.base_amount, price)
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
            base_asset, _ = dasset.assets_from_market(broker_order.market)
            exchange_withdrawal_id = dasset.crypto_withdrawal_create_req(base_asset, broker_order.base_amount, broker_order.recipient)
            exchange_withdrawal = ExchangeWithdrawal(exchange_withdrawal_id)
            broker_order.exchange_withdrawal = exchange_withdrawal
            broker_order.status = broker_order.STATUS_WITHDRAW
            updated_records.append(exchange_withdrawal)
            updated_records.append(broker_order)
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

def broker_order_update_and_commit(db_session, broker_order):
    while True:
        updated_records = _broker_order_update(broker_order)
        if not updated_records:
            return
        for rec in updated_records:
            db_session.add(rec)
        db_session.commit()
