import gevent
import logging
from dataclasses import dataclass

from flask import flash

from app_core import app, db
import dasset
import assets
import email_utils
import depwith
import broker
import remit
import utils
from task_manager import TaskManager
import wallet
from ln import LnRpc, _msat_to_sat
from models import BalanceUpdate
import websocket
import utils
import security

logger = logging.getLogger(__name__)

_task_info: dict[str, dict[str, 'TaskInfo']] = {}

@dataclass
class TaskInfo:
    STATUS_INPROGRESS = 'in progress'
    STATUS_ERROR = 'error'
    STATUS_SUCCESS = 'success'

    status: str
    message: str

def get_task_info_category(category: str):
    logger.info("calling get_task_info(), current: _task_info = {0}".format(_task_info))
    if category in _task_info:
        return _task_info[category]
    return {}

def clear_task_info(category: str, task_uid: str):
    logger.info("calling clear_task_info(), current: _task_info = {0}".format(_task_info))
    if category in _task_info:
        infos = _task_info[category]
        if task_uid in infos:
            infos.pop(task_uid)

def store_task_info(category: str, task_uid: str, info: TaskInfo):
    logger.info("calling store_task_info(), current: _task_info = {0}".format(_task_info))
    if category not in _task_info:
        _task_info[category] = {}
    infos = _task_info[category]
    infos[task_uid] = info

def flash_and_clear_tasks(category: str):
    infos = get_task_info_category(category).copy()
    for task_uid in infos:
        info = infos[task_uid]
        color = 'primary'
        if info.status == info.STATUS_SUCCESS:
            color = 'success'
        elif info.status == info.STATUS_ERROR:
            color = 'danger'
        flash(f'pay invoice task {info.status}: {info.message}', color)
        if info.status in [info.STATUS_ERROR, info.STATUS_SUCCESS]:
            clear_task_info(category, task_uid)

#
# Periodic task functions, !assume we have a flask app context!
#

def process_depwith_and_broker_orders():
    logger.info('process deposits..')
    depwith.fiat_deposits_update(db.session)
    utils.yield_gevent()
    depwith.crypto_deposits_check(db.session)
    utils.yield_gevent()
    logger.info('process withdrawals..')
    depwith.fiat_withdrawals_update(db.session)
    utils.yield_gevent()
    # process btc onchain withdrawals before other crypto withdrawals (so we can batch all outstanding)
    depwith.btc_onchain_withdrawals_update(db.session)
    utils.yield_gevent()
    depwith.crypto_withdrawals_update(db.session)
    utils.yield_gevent()
    logger.info('process broker orders..')
    broker.broker_orders_update(db.session)

def process_remits():
    logger.info('process remits..')
    remit.remits_update(db.session)

def _process_btc_tx_index():
    logger.info('process btc tx index..')
    wallet.btc_transactions_index()

def _process_dasset_cache():
    # logger.info('process dasset cache..')
    dasset.order_book_refresh_cache(10)
    dasset.markets_refresh_cache(10)

def _tf_method_check():
    # for some reason `security.tf_method()` randomly starts failing after some time
    # it is difficult to debug because we dont know how or what causes it to start happening
    # this is a stop gap solution to send an email to the admin when it starts failing
    try:
        with app.app_context():
            security.tf_method()
    except Exception as e:
        logger.error('tf_method() failed: %s', e)
        email_utils.send_email('tf_method() failed', str(e))

#
# One off task functions, !assume we have a flask app context
#

def process_broker_order(token: str):
    broker.broker_order_update(db.session, token)

def update_withdrawal(asset: str, token: str):
    if assets.asset_is_crypto(asset):
        depwith.crypto_withdrawal_update(db.session, token)
    else:
        depwith.fiat_withdrawal_update(db.session, token)

def update_remit(token: str):
    remit.remit_update(db.session, token)

def ln_rebalance_channels(oscid: str, iscid: str, amount: int):
    category = 'ln_rebalance_channels'
    info_str = 'Rebalancing {0} -> {1} with {2} sats'.format(oscid, iscid, amount)
    task_uid = utils.generate_key()
    store_task_info(category, task_uid, TaskInfo(TaskInfo.STATUS_INPROGRESS, info_str))
    try:
        LnRpc().rebalance_channel(oscid, iscid, amount)
        email_utils.send_email('Channel Rebalance Successful', info_str)
        store_task_info(category, task_uid, TaskInfo(TaskInfo.STATUS_SUCCESS, info_str))
    except Exception as e:
        logger.error('ln_rebalance_channels error: %s', e)
        info_str = 'error: {0}'.format(e)
        store_task_info(category, task_uid, TaskInfo(TaskInfo.STATUS_ERROR, info_str))

def send_email_task(subject: str, msg: str, recipient: str | None = None, attachment: str | None = None):
    if not recipient:
        recipient = app.config["ADMIN_EMAIL"]
    assert recipient
    if app.config["USE_SENDGRID"]:
        return email_utils.send_email_sendgrid(logger, subject, msg, recipient, attachment)
    return email_utils.send_email_postfix(logger, subject, msg, recipient, attachment)

def ln_pay_to_invoice(bolt11: str):
    category = 'ln_pay_to_invoice'
    task_uid = utils.generate_key()
    info_str = 'Paid Invoice: {0}'.format(utils.shorten(bolt11))
    store_task_info(category, task_uid, TaskInfo(TaskInfo.STATUS_INPROGRESS, info_str))
    try:
        LnRpc().pay(bolt11)
        email_utils.send_email('Paid Invoice', info_str)
        store_task_info(category, task_uid, TaskInfo(TaskInfo.STATUS_SUCCESS, info_str))
    except Exception as e:
        logger.error('%s error: %s', category, e)
        info_str = 'error: {0}'.format(e)
        store_task_info(category, task_uid, TaskInfo(TaskInfo.STATUS_ERROR, info_str))
    return info_str

#
# Non-terminating task functions
#

def _process_ln_invoices_loop():
    gevent.sleep(10, False)  # HACK: wait for the ln server to start
    lastpay_index = 0
    while True:
        try:
            if lastpay_index == 0:
                lastpay_index = LnRpc().lastpay_index()
            pay, err = wallet.ln_any_deposit_completed(lastpay_index)
            if err:
                logger.debug('wait_any_invoice failed: "%s"', err)
                gevent.sleep(2, False)  # probably timeout so we wait a short time before polling again
            else:
                logger.info('wait_any_invoice: %s', pay)
                with app.app_context():
                    if pay and pay['status'] == 'paid':
                        label = pay['label']
                        payment_hash = pay['payment_hash']
                        bolt11 = pay['bolt11']
                        lastpay_index = pay['pay_index']
                        description = pay['description']
                        msat = pay['msatoshi']
                        sat = _msat_to_sat(msat)
                        deposit = BalanceUpdate.from_wallet_reference(db.session, bolt11)
                        if not deposit or not deposit.crypto or deposit.type != deposit.TYPE_DEPOSIT or deposit.asset != assets.BTC.symbol:
                            logger.error('{deposit.token} does not match BTC LN deposit!')
                            continue
                        email = None
                        if deposit:
                            email = deposit.user.email
                        # update user with websocket event
                        websocket.ln_invoice_paid_event(label, payment_hash, bolt11, email, description, sat)
                        # yield to other tasks
                        utils.yield_gevent()
                        # update deposits from wallet
                        depwith.crypto_wallet_deposits_check(db.session)
        except ConnectionError as e:
            logger.error('wait_any_invoice error: %s', e)
            gevent.sleep(5, False)

#
# Init tasks
#

task_manager = TaskManager()
task_manager.repeated('deposits, withdrawals, orders', process_depwith_and_broker_orders, 5)
task_manager.repeated('remits', process_remits, 5)
task_manager.repeated('btc tx index', _process_btc_tx_index, 60)
task_manager.repeated('dasset cache', _process_dasset_cache, 0)
task_manager.repeated('tf_method() check', _tf_method_check, 5)
task_manager.non_terminating('ln invoices', _process_ln_invoices_loop)
