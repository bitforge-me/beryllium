import logging
import threading

from sqlalchemy.orm import scoped_session
from sqlalchemy.sql import func

from models import User, FiatDbTransaction

logger = logging.getLogger(__name__)
_lock = threading.Lock()

def __balance(session: scoped_session, asset: str, user: User):
    ## assumes lock is held
    query = session.query(func.sum(FiatDbTransaction.amount)) \
        .filter(FiatDbTransaction.asset == asset)
    if user:
        query = query.filter(FiatDbTransaction.user_id == user.id)
    credit = query.filter(FiatDbTransaction.action == FiatDbTransaction.ACTION_CREDIT).scalar()
    debit = query.filter(FiatDbTransaction.action == FiatDbTransaction.ACTION_CREDIT).scalar()
    return credit - debit

def __balance_total(session: scoped_session, asset: str):
    ## assumes lock is held
    return __balance(session, asset, None)

def user_balance(session: scoped_session, asset: str, user: User):
    with _lock:
        return __balance(session, asset, user)

def balance_total(session: scoped_session, asset: str):
    with _lock:
        return __balance_total(session, asset)

def tx_create(session: scoped_session, user: User, action: str, asset: str, amount: int, attachment: str):
    logger.info('%s: %s: %s, %s, %s', user.email, action, asset, amount, attachment)
    with _lock:
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
        return FiatDbTransaction(user, action, asset, amount, attachment)
