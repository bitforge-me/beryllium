from datetime import datetime, timedelta
import logging
from dataclasses import dataclass

import email_utils

logger = logging.getLogger(__name__)

@dataclass
class EventType:
    name: str
    attempts: int
    last_attempt: datetime
    expire_next: datetime
    ok: bool

LOGIN = EventType(name='login', attempts=0, last_attempt=datetime.now(), expire_next=datetime.now(), ok=True)
WITHDRAWAL = EventType(name='withdrawal', attempts=0, last_attempt=datetime.now(), expire_next=datetime.now(), ok=True)
DATA = dict(login=LOGIN, withdrawal=WITHDRAWAL)

def _attempt(event_type: EventType):
    if not event_type.ok:
        return

    now = datetime.now()
    while event_type.expire_next < now and event_type.attempts > 0:
        event_type.attempts -= 1
        event_type.expire_next += timedelta(minutes=1)
    if event_type.attempts == 0:
        event_type.expire_next = now + timedelta(minutes=1)
    event_type.attempts += 1
    event_type.last_attempt = now
    if event_type.attempts > 10:
        for name, event_type in DATA.items():
            event_type.ok = False
        email_utils.email_tripwire_notification(logger)

def login_attempt():
    _attempt(LOGIN)

def withdrawal_attempt():
    _attempt(WITHDRAWAL)
