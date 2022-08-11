import logging
from importlib.metadata import version

def log_socketio_version(logger):
    logger.info('python-socketio version: %s', version('python-socketio'))
    logger.info('python-engineio version: %s', version('python-engineio'))

def setup_logging(logger, level):
    if level < logging.WARNING:
        # geventwebsocket.handler logger pollutes our log with http requests at the INFO level
        # we raise the logging level for that module because we can see the http request in our
        # proxy server logs and want to make the app logs easier to parse
        logging.getLogger('geventwebsocket.handler').setLevel(logging.WARNING)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    return ch
