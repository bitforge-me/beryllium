import logging
from importlib.metadata import version

def log_socketio_version(logger):
    logger.info('python-socketio version: %s', version('python-socketio'))
    logger.info('python-engineio version: %s', version('python-engineio'))

def setup_logging(logger, level):
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()
    return ch
