# from https://github.com/maximilize/geventconnectionpool (with modifications)

import time
import gevent
import logging

from queue import Full
from gevent.lock import Semaphore
from gevent.event import Event
from sqlalchemy.pool import Pool  # pyright: ignore [reportGeneralTypeIssues]  -- WTF pywright!

logger = logging.getLogger(__name__)

class GeventConnectionPool(Pool):
    def __init__(self, creator, max_connections=None, reserve_connections=None, connection_idle_timeout=30, is_full_event='wait', **kw):
        Pool.__init__(self, creator, **kw)

        self.max_connections = max_connections or 5
        self.reserve_connections = reserve_connections or 1
        self.connection_idle_timeout = connection_idle_timeout
        self.is_full_event = is_full_event

        self._lock = Semaphore()
        self._available = list()
        self._inuse = list()
        self._timeouter = gevent.spawn_later(self.connection_idle_timeout, self._timeout)
        self._is_not_full = Event()

    def recreate(self):
        logger.debug('Pool recreating')
        return self.__class__(self._creator, recycle=self._recycle, echo=self.echo, logging_name=self._orig_logging_name, reset_on_return=self._reset_on_return, pre_ping=self._pre_ping, _dispatch=self.dispatch, dialect=self._dialect)  # pyright: ignore [reportGeneralTypeIssues]  -- WTF pywright!

    def dispose(self):
        with self._lock:
            while self._available:
                t, conn = self._available.pop()
                conn.close()
        logger.debug('Pool disposed.')

    def _timeout(self):
        try:
            with self._lock:
                while self._available and len(self._available) + len(self._inuse) > self.reserve_connections and self._available[-1][0] + self.connection_idle_timeout < time.time():
                    t, connection = self._available.pop(-1)
                    connection.close()
                    logger.debug('closing timed out connection after %0.2f seconds (%s available, %s in use)', time.time() - t, len(self._available), len(self._inuse))
        finally:
            self._timeouter = gevent.spawn_later(self.connection_idle_timeout, self._timeout)

    def _do_get(self):
        while True:
            try:
                with self._lock:
                    if self._available:
                        t, connection = self._available.pop(0)
                        logger.debug('pop connection (%s available, %s in use)', len(self._available), len(self._inuse))
                    else:
                        if self.max_connections is not None and len(self._inuse) >= self.max_connections:
                            self._is_not_full.clear()
                            raise Full('max connections of %s reached' % self.max_connections)
                        connection = self._create_connection()  # pyright: ignore [reportGeneralTypeIssues]  -- WTF pywright!
                        logger.debug('new connection (%s available, %s in use)', len(self._available), len(self._inuse) + 1)
                    self._inuse.append(connection)
            except Full:
                if self.is_full_event == 'wait':
                    logger.debug('pool full. waiting for available slot (%s available, %s in use)', len(self._available), len(self._inuse))
                    self._is_not_full.wait()
                else:
                    raise
            else:
                return connection

    def _do_return_conn(self, connection):
        with self._lock:
            logger.debug('release connection (%s available, %s in use)', len(self._available), len(self._inuse))
            self._inuse.remove(connection)
            self._available.insert(0, (time.time(), connection))
            self._is_not_full.set()
