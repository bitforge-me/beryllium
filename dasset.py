import logging

import requests

from app_core import app

logger = logging.getLogger(__name__)

DASSET_API_SECRET = app.config['DASSET_API_SECRET']
DASSET_ACCOUNT_ID = app.config['DASSET_ACCOUNT_ID']
ASSET_LIST = [x.strip() for x in app.config['ASSET_LIST'].split(',')]
MARKET_LIST = [x.strip() for x in app.config['MARKET_LIST'].split(',')]

URL_BASE = 'https://api.dassetx.com/api'

def req(endpoint):
    url = URL_BASE + endpoint
    headers = dict()
    headers['x-api-key'] = DASSET_API_SECRET
    headers['x-account-id'] = DASSET_ACCOUNT_ID
    logger.info('   GET - ' + url)
    r = requests.get(url, headers=headers)
    return r

def assets(asset=None):
    endpoint = '/currencies'
    if asset:
        endpoint = f'/currencies/{asset}'
    r = req(endpoint)
    if r.status_code == 200:
        assets = r.json()
        assets = [a for a in assets if a['symbol'] in ASSET_LIST]
        return assets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def markets():
    endpoint = '/markets'
    r = req(endpoint)
    if r.status_code == 200:
        markets = r.json()
        markets = [m for m in markets if m['symbol'] in MARKET_LIST]
        return markets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def order_book(symbol):
    endpoint = f'/markets/{symbol}/orderbook'
    r = req(endpoint)
    if r.status_code == 200:
        return r.json()
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None
