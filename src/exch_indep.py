import logging
from decimal import Decimal as Dec
import json
import time
from typing import Tuple

import independentreserve as ir

from app_core import app
import assets
import exch
from exch import BROKER_ORDER_FEE, BROKER_ORDER_FEE_FIXED

logger = logging.getLogger(__name__)

_assets = {assets.BTC.symbol: assets.BTC, assets.NZD.symbol: assets.NZD}
# match assets to independent reserver 'Currency Codes'
_asset_table = {assets.BTC.symbol: 'Xbt', assets.NZD.symbol: 'Nzd'}
# match currency codes to assets
_cc_table = {v: k for k, v in _asset_table.items()}

# cache globals
_orderbook_cache: dict[str, Tuple[float, exch.ExchOrderbook]] = {}
_markets_cache: Tuple[float, list[exch.ExchMarket]] | None = None
CACHE_EXPIRY = 30

def _markets_data(pub: ir.PublicMethods, use_cache: bool) -> list[exch.ExchMarket] | None:
    global _markets_cache
    if use_cache:
        # see if we have a cached version to return
        if _markets_cache:
            timestamp, markets = _markets_cache
            # if timestamp + cache expiry is greater then current timestamp then cache still valid
            if timestamp + CACHE_EXPIRY > time.time():
                return markets
            logger.error('cache hit failed, ts: %f, time: %f', timestamp, time.time())
    # request the current data
    r = pub.get_order_minimum_volumes()
    if r.status_code == 200:
        markets = []
        min_volumes = r.json()
        for symbol, market in assets.MARKETS.items():
            primary_currency = _asset_table[market.base_asset.symbol]
            if primary_currency in min_volumes:
                min_trade = Dec(min_volumes[primary_currency])
                markets.append(exch.ExchMarket(symbol, market.base_asset.symbol, market.quote_asset.symbol, 8, min_trade))
        # save to the cache with timestamp
        _markets_cache = time.time(), markets
        # return result to caller
        return markets
    logger.error('markets data request failed: %d, %s', r.status_code, r.text[:100])
    return None

def _order_book_data(pub: ir.PublicMethods, market: str, use_cache: bool) -> exch.ExchOrderbook | None:
    if use_cache:
        # see if we have a cached version to return
        if market in _orderbook_cache:
            timestamp, book = _orderbook_cache[market]
            # if timestamp + cache expiry is greater then current timestamp then cache still valid
            if timestamp + CACHE_EXPIRY > time.time():
                return book
            logger.error('cache hit failed, ts: %f, time: %f', timestamp, time.time())
    # request the current data
    base_asset, quote_asset = assets.assets_from_market(market)
    primary_currency = _asset_table[base_asset]
    secondary_currency = _asset_table[quote_asset]
    r = pub.get_order_book(primary_currency, secondary_currency)
    if r.status_code == 200:
        order_book = r.json()
        bids = []
        for buy_order in order_book['BuyOrders']:
            price = Dec(buy_order['Price'])
            volume = Dec(buy_order['Volume'])
            bids.append(exch.ExchOrderbookEntry(quantity=volume, rate=price))
        asks = []
        for sell_order in order_book['SellOrders']:
            price = Dec(sell_order['Price'])
            volume = Dec(sell_order['Volume'])
            asks.append(exch.ExchOrderbookEntry(quantity=volume, rate=price))
        # save to the cache with timestamp
        book = exch.ExchOrderbook(bids, asks)
        _orderbook_cache[market] = time.time(), book
        # return result to caller
        return book
    logger.error('order book request failed: %d, %s', r.status_code, r.text[:100])
    return None

#
# Mock Exchange
#

class ExchIndep(exch.ExchInterface):

    def __init__(self, api_key: str, api_secret: str):
        self.pub = ir.PublicMethods()
        self.prv = ir.PrivateMethods(api_key, api_secret)

    def markets_data(self, use_cache: bool) -> list[exch.ExchMarket] | None:
        return _markets_data(self.pub, use_cache)

    def market_data(self, market: str, use_cache: bool) -> exch.ExchMarket | None:
        markets = self.markets_data(use_cache)
        if markets:
            for m in markets:
                if m.symbol == market:
                    return m
        return None

    def order_book_data(self, market: str, use_cache: bool) -> tuple[exch.ExchOrderbook | None, Dec, dict[str, Dec]]:
        return _order_book_data(self.pub, market, use_cache), BROKER_ORDER_FEE, BROKER_ORDER_FEE_FIXED

    def account_balances(self, asset: str | None = None, quiet=False) -> list[exch.ExchBalance] | None:
        balances = []
        r = self.prv.get_accounts()
        if r.status_code == 200:
            accounts = r.json()
            for account in accounts:
                currency = account['CurrencyCode']
                if currency in _cc_table:
                    symbol = _cc_table[currency]
                    balances.append(exch.ExchBalance(symbol, _assets[symbol].name, Dec(account['TotalBalance']), Dec(account['AvailableBalance'])))
            return balances
        logger.error('account balance request failed: %d, %s', r.status_code, r.text[:100])
        return None

    def order_create(self, market: str, side: assets.MarketSide, amount: Dec, price: Dec) -> str | None:
        base_asset, quote_asset = assets.assets_from_market(market)
        primary_currency = _asset_table[base_asset]
        secondary_currency = _asset_table[quote_asset]
        order_type = 'LimitBid'
        if assets.market_side_is(side, assets.MarketSide.ASK):
            order_type = 'LimitAsk'
        r = self.prv.place_limit_order(str(price), str(amount), primary_currency, secondary_currency, order_type)
        if r.status_code == 200:
            return r.json()['OrderGuid']
        logger.error('order create request failed: %d, %s', r.status_code, r.text[:100])
        return None

    def order_details(self, order_id: str, market: str) -> None | exch.ExchOrder:
        r = self.prv.get_order_details(order_id)
        if r.status_code == 200:
            order = r.json()
            base_asset = _cc_table[order['PrimaryCurrencyCode']]
            quote_asset = _cc_table[order['SecondaryCurrencyCode']]
            date = order['CreatedTimestampUtc']
            side = assets.MarketSide.ASK
            if order['Type'] == 'LimitBid':
                side = assets.MarketSide.BID
            base_amount = Dec(order['VolumeOrdered'])
            quote_amount = Dec(order['Price'])
            base_amount_filled = Dec(order['VolumeFilled'])
            return exch.ExchOrder(id=order_id, status=order['Status'], base_asset=base_asset, quote_asset=quote_asset, date=date, side=side, base_amount=base_amount, quote_amount=quote_amount, base_amount_filled=base_amount_filled)
        logger.error('order details request failed: %d, %s', r.status_code, r.text[:100])
        return None

    def markets_refresh_cache(self, margin: int):
        if _markets_cache:
            timestamp, _ = _markets_cache
            if timestamp + CACHE_EXPIRY - margin > time.time():
                return
        #logger.info('refresh cache for %s', MARKETS_KEY)
        _markets_data(self.pub, False)

    def order_book_refresh_cache(self, margin: int):
        for symbol in assets.MARKETS:
            if symbol in _orderbook_cache:
                timestamp, _ = _orderbook_cache[symbol]
                if timestamp + CACHE_EXPIRY - margin > time.time():
                    continue
            #logger.info('refresh cache for %s', symbol)
            _order_book_data(self.pub, symbol, False)
