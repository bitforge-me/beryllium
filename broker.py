import datetime

import payments_core
import dasset
from models import ExchangeOrder

def _broker_order_update(broker_order):
    updated_records = []
    # check payment
    if broker_order.status == broker_order.STATUS_READY:
        if broker_order.windcave_payment_request:
            payment_req = broker_order.windcave_payment_request
            payments_core.payment_request_status_update(payment_req)
            updated_records.append(payment_req)
            if payment_req.status == payment_req.STATUS_CANCELLED:
                broker_order.status = broker_order.STATUS_CANCELLED
                updated_records.append(broker_order)
                return updated_records
            if payment_req.status == payment_req.STATUS_COMPLETED:
                broker_order.status = broker_order.STATUS_CONFIRMED
                updated_records.append(broker_order)
                return updated_records
    # create exchange order
    if broker_order.status == broker_order.STATUS_CONFIRMED:
        price = broker_order.quote_amount / broker_order.base_amount
        exchange_order = dasset.order_create_req(broker_order.market, dasset.MarketSide.BID, broker_order.base_amount, price)
        exchange_order_id = exchange_order['order']['orderId']
        exchange_order = ExchangeOrder(exchange_order_id)
        broker_order.exchange_order = exchange_order
        broker_order.status = broker_order.STATUS_EXCHANGE
        updated_records.append(exchange_order)
        updated_records.append(broker_order)
        return updated_records
    # create withdrawal
    if broker_order.status == broker_order.STATUS_EXCHANGE:
        #TODO - check exchange order
        #TODO - create exchange withdrawal
        #broker_order.status = broker_order.STATUS_WITHDRAW
        #updated_records.append(broker_order)
        return updated_records
    # check withdrawal
    if broker_order.status == broker_order.STATUS_WITHDRAW:
        #TODO - check exchange withdrawal
        #broker_order.status = broker_order.STATUS_COMPLETE
        #updated_records.append(broker_order)
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
