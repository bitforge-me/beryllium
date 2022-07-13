from decimal import Decimal
import logging
from gevent.lock import Semaphore

from sqlalchemy.orm.session import Session
from sqlalchemy.sql import func

from models import User, FiatDbTransaction
from assets import ASSETS, asset_int_to_dec

logger = logging.getLogger(__name__)
_lock = Semaphore()


def __balance(session: Session, asset: str, user: User | None):
    # !assumes lock is held!
    query = session.query(func.sum(FiatDbTransaction.amount)).filter(
        FiatDbTransaction.asset == asset
    )
    if user:
        query = query.filter(FiatDbTransaction.user_id == user.id)
    credit = query.filter(
        FiatDbTransaction.action == FiatDbTransaction.ACTION_CREDIT
    ).scalar()
    debit = query.filter(
        FiatDbTransaction.action == FiatDbTransaction.ACTION_DEBIT
    ).scalar()
    if credit is None and debit is None:
        return 0
    if debit is None:
        return credit
    if credit is None:
        return -debit
    return credit - debit


def __balance_total(session: Session, asset: str):
    # !assumes lock is held!
    return __balance(session, asset, None)


def user_balance(session: Session, asset: str, user: User):
    with _lock:
        return __balance(session, asset, user)


def user_balances(session: Session, user: User):
    with _lock:
        balances = {}
        for asset in ASSETS:
            balances[asset] = __balance(session, asset, user)
        return balances


def funds_available_user(session: Session, user: User, asset: str, amount: Decimal):
    balance = user_balance(session, asset, user)
    balance_dec = asset_int_to_dec(asset, balance)
    return balance_dec >= amount


def balance_total(session: Session, asset: str):
    with _lock:
        return __balance_total(session, asset)


def tx_create(user: User, action: str, asset: str, amount: int, attachment: str):
    logger.info('%s: %s: %s, %s, %s', user.email, action, asset, amount, attachment)
    assert amount > 0
    assert action in (FiatDbTransaction.ACTION_CREDIT, FiatDbTransaction.ACTION_DEBIT)
    with _lock:
        return FiatDbTransaction(user, action, asset, amount, attachment)
