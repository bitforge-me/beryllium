import logging
import threading

from models import Role, User, Permission, PayDbTransaction

logger = logging.getLogger(__name__)
lock = threading.Lock()
balances = None

def __balance(user):
    ## assumes lock is held
    if not user.token in balances:
        return 0
    return balances[user.token]

def __balance_total():
    ## assumes lock is held
    balance = 0
    for val in balances.values():
        balance += val
    return balance

def __tx_play(tx):
    ## assumes lock is held
    if not tx.sender.token in balances:
        balances[tx.sender.token] = 0
    if tx.recipient and not tx.recipient.token in balances:
        balances[tx.recipient.token] = 0
    if tx.action == tx.ACTION_ISSUE:
        balances[tx.sender.token] += tx.amount
    if tx.action == tx.ACTION_TRANSFER:
        balances[tx.sender.token] -= tx.amount
        balances[tx.recipient.token] += tx.amount
    if tx.action == tx.ACTION_DESTROY:
        balances[tx.sender.token] -= tx.amount

def __tx_play_all(session):
    ## assumes lock is held
    global balances
    assert(not balances)
    balances = {}
    for tx in PayDbTransaction.all(session):
        __tx_play(tx)

def __check_balances_inited(session):
    ## assumes lock is held
    # check balances has been initialized
    if balances == None:
        logger.info('balances not initialized, initializing now..')
        __tx_play_all(session)

def user_balance_from_user(session, user):
    with lock:
        __check_balances_inited(session)
        return __balance(user)

def user_balance(session, api_key):
    if not api_key.has_permission(Permission.PERMISSION_BALANCE):
        return -1
    return user_balance_from_user(session, api_key.user)

def balance_total(session):
    with lock:
        __check_balances_inited(session)
        return __balance_total()

def tx_play_all(session):
    with lock:
        __tx_play_all(session)

def tx_create_and_play(session, api_key, action, recipient_email, amount, attachment):
    logger.info('{} ({}): {}: {}, {}, {}'.format(api_key.token, api_key.user.email, action, recipient_email, amount, attachment))
    with lock:
        __check_balances_inited(session)
        error = ''
        user = api_key.user
        if not user.is_active:
            error = '{}: {} is not active'.format(action, user.email)
        elif amount <= 0:
            error = '{}: amount ({}) is less then or equal to zero'.format(action, amount)
        if error:
            logger.error(error)
            return None, error
        recipient = User.from_email(session, recipient_email)
        if action == PayDbTransaction.ACTION_ISSUE:
            if not api_key.has_permission(Permission.PERMISSION_ISSUE):
                error = 'ACTION_ISSUE: {} is not authorized'.format(api_key.token)
            elif not user.has_role(Role.ROLE_ADMIN):
                error = 'ACTION_ISSUE: {} is not authorized'.format(user.email)
            elif not recipient == user:
                error = 'ACTION_ISSUE: recipient should be {}'.format(user.email)
        if action == PayDbTransaction.ACTION_TRANSFER:
            user_balance = __balance(user)
            if not api_key.has_permission(Permission.PERMISSION_TRANSFER):
                error = 'ACTION_TRANSFER: {} is not authorized'.format(api_key.token)
            elif not recipient:
                error = 'ACTION_TRANSFER: recipient ({}) is not valid'.format(recipient_email)
            elif user_balance < amount:
                error = 'ACTION_TRANSFER: user balance ({}) is too low'.format(user_balance)
        if action == PayDbTransaction.ACTION_DESTROY:
            user_balance = __balance(user)
            if not api_key.has_permission(Permission.PERMISSION_TRANSFER):
                error = 'ACTION_TRANSFER: {} is not authorized'.format(api_key.token)
            elif not recipient == user:
                error = 'ACTION_ISSUE: recipient should be {}'.format(user.email)
            elif user_balance < amount:
                error = 'ACTION_DESTROY: user balance ({}) is too low'.format(user_balance)
        if error:
            logger.error(error)
            return None, error
        tx = PayDbTransaction(action, user, recipient, amount, attachment)
        __tx_play(tx)
        session.add(tx)
        session.commit()
        return tx, ''