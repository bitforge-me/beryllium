import logging
import threading
from types import SimpleNamespace

from models import FiatDbTransaction

logger = logging.getLogger(__name__)
_user_balances = SimpleNamespace(lock=threading.Lock(), kvstore=None)

def __balance(asset, user):
    ## assumes lock is held
    if not asset in _user_balances.kvstore:
        return 0
    if not user.token in _user_balances.kvstore[asset]:
        return 0
    return _user_balances.kvstore[asset][user.token]

def __balance_total(asset):
    ## assumes lock is held
    balance = 0
    if asset in _user_balances.kvstore:
        for val in _user_balances.kvstore[asset].values():
            balance += val
    return balance

def __tx_play(txn):
    ## assumes lock is held
    if not txn.asset in _user_balances.kvstore:
        _user_balances.kvstore[txn.asset] = {}
    asset_balances = _user_balances.kvstore[txn.asset]
    if not txn.user.token in asset_balances:
        asset_balances[txn.user.token] = 0
    if txn.action == txn.ACTION_CREDIT:
        asset_balances[txn.user.token] += txn.amount
    elif txn.action == txn.ACTION_DEBIT:
        asset_balances[txn.user.token] -= txn.amount

def __tx_play_all(session):
    ## assumes lock is held
    assert not _user_balances.kvstore
    _user_balances.kvstore = {}
    for tx in FiatDbTransaction.all(session):
        __tx_play(tx)

def __check_balances_inited(session):
    ## assumes lock is held
    # check _user_balances.kvstore has been initialized
    if _user_balances.kvstore is None:
        logger.info('_user_balances.kvstore not initialized, initializing now..')
        __tx_play_all(session)

def user_balance(session, asset, user):
    with _user_balances.lock:
        __check_balances_inited(session)
        return __balance(asset, user)

def balance_total(session, asset):
    with _user_balances.lock:
        __check_balances_inited(session)
        return __balance_total(asset)

def tx_play_all(session):
    with _user_balances.lock:
        __tx_play_all(session)

def tx_create_and_play(session, user, action, asset, amount, attachment):
    logger.info('%s: %s: %s, %s, %s', user.email, action, asset, amount, attachment)
    with _user_balances.lock:
        __check_balances_inited(session)
        error = ''
        if not user.is_active:
            error = f'{action}: {user.email} is not active'
        elif amount <= 0:
            error = f'{action}: amount ({amount}) is less then or equal to zero'
        elif not action in (FiatDbTransaction.ACTION_CREDIT, FiatDbTransaction.ACTION_DEBIT):
            error = 'invalid action'
        if error:
            logger.error(error)
            return None
        tx = FiatDbTransaction(user, action, asset, amount, attachment)
        __tx_play(tx)
        return tx
