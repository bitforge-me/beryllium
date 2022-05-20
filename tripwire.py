from time import time
import logging
from dataclasses import dataclass

import email_utils

logger = logging.getLogger(__name__)

@dataclass
class EventType:
    name: str
    attempts: int
    last_attempt: float
    # pylint: disable=invalid-name
    ok: bool

LOGIN = EventType(name='login', attempts=0, last_attempt=time(), ok=True)
WITHDRAWAL = EventType(name='withdrawal', attempts=0, last_attempt=time(), ok=True)
DATA = dict(login=LOGIN, withdrawal=WITHDRAWAL)

def login_attempt():
    if not LOGIN.ok:
        return

    now = time()
    while LOGIN.last_attempt < now and LOGIN.attempts > 0:
        LOGIN.attempts -= 1
        LOGIN.last_attempt += 60
    LOGIN.attempts += 1
    if LOGIN.attempts > 10:
        LOGIN.ok = False
        WITHDRAWAL.ok = False
        email_utils.email_tripwire_notification(logger)

def withdrawal_attempt():
    if not WITHDRAWAL.ok:
        return

    now = time()
    while WITHDRAWAL.last_attempt < now and WITHDRAWAL.last_attempt > 0:
        WITHDRAWAL.attempts -= 1
        WITHDRAWAL.last_attempt += 60
    WITHDRAWAL.attempts += 1
    if WITHDRAWAL.attempts > 10:
        LOGIN.ok = False
        WITHDRAWAL.ok = False
        email_utils.email_tripwire_notification(logger)
