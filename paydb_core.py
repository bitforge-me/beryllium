import logging
import threading

from models import User, Transaction

logger = logging.getLogger(__name__)
lock = threading.Lock()
balances = None

def __balance(user):
    ## assumes lock is held
    if not user.email in balances:
        return 0
    return balances[user.email]

def __tx_play(tx):
    ## assumes lock is held
    if not tx.sender.email in balances:
        balances[tx.sender.email] = 0
    if tx.recipient and not tx.recipient.email in balances:
        balances[tx.recipient.email] = 0
    if tx.action == tx.ACTION_ISSUE:
        balances[tx.sender.email] += tx.amount
    if tx.action == tx.ACTION_TRANSFER:
        balances[tx.sender.email] -= tx.amount
        balances[tx.recipient.email] += tx.amount
    if tx.action == tx.ACTION_DESTROY:
        balances[tx.sender.email] -= tx.amount

def __tx_play_all(session):
    ## assumes lock is held
    global balances
    assert(not balances)
    balances = {}
    for tx in Transaction.all(session):
        __tx_play(tx)

def __check_balances_inited(session):
    ## assumes lock is held
    # check balances has been initialized
    if balances == None:
        logger.info('balances not initialized, initializing now..')
        __tx_play_all(session)

def user_balance(session, user):
    with lock:
        __check_balances_inited(session)
        return __balance(user)

def tx_play_all(session):
    with lock:
        __tx_play_all(session)

def tx_create_and_play(session, user, action, recipient_email, amount, attachment):
    logger.info('{}: {}: {}, {}, {}'.format(user.email, action, recipient_email, amount, attachment))
    with lock:
        __check_balances_inited(session)
        error = ''
        if not user.is_active:
            error = '{}: {} is not active'.format(action, user.email)
        elif amount <= 0:
            error = '{}: amount ({}) is less then or equal to zero'.format(action, amount)
        if error:
            logger.error(error)
            return None, error
        recipient = User.from_email(session, recipient_email)
        if action == Transaction.ACTION_ISSUE:
            if not user.has_role('admin'):
                error = 'ACTION_ISSUE: {} is not authorized'.format(user.email)
            elif not recipient == user:
                error = 'ACTION_ISSUE: recipient should be {}'.format(user.email)
        if action == Transaction.ACTION_TRANSFER:
            user_balance = __balance(user)
            if not recipient:
                error = 'ACTION_TRANSFER: recipient ({}) is not valid'.format(recipient_email)
            elif user_balance < amount:
                error = 'ACTION_TRANSFER: user balance ({}) is too low'.format(user_balance)
        if action == Transaction.ACTION_DESTROY:
            user_balance = __balance(user)
            if not recipient == user:
                error = 'ACTION_ISSUE: recipient should be {}'.format(user.email)
            elif user_balance < amount:
                error = 'ACTION_DESTROY: user balance ({}) is too low'.format(user_balance)
        if error:
            logger.error(error)
            return None, error
        tx = Transaction(action, user, recipient, amount, attachment)
        __tx_play(tx)
        session.add(tx)
        session.commit()
        return tx, ''