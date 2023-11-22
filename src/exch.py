from dataclasses import dataclass
import logging
from decimal import Decimal as Dec
import json
from enum import Enum
from typing import Any

from app_core import app
import assets

logger = logging.getLogger(__name__)

BROKER_ORDER_FEE = Dec(app.config['BROKER_ORDER_FEE'])
BROKER_ORDER_FEE_FIXED: dict[str, Dec] = json.loads(app.config['BROKER_ORDER_FEE_FIXED'])
for key in BROKER_ORDER_FEE_FIXED:
    BROKER_ORDER_FEE_FIXED[key] = Dec(BROKER_ORDER_FEE_FIXED[key])


class QuoteResult(Enum):
    OK = 0
    AMOUNT_TOO_LOW = 1
    INSUFFICIENT_LIQUIDITY = 2
    MARKET_API_FAIL = 3

@dataclass
class QuoteTotalPrice:
    amountBaseAsset: Dec
    amountQuoteAsset: Dec
    feeQuoteAsset: Dec
    fixedFeeQuoteAsset: Dec
    market: str
    err: QuoteResult

    @classmethod
    def error(cls, err: QuoteResult):
        return cls(Dec(0), Dec(0), Dec(0), Dec(0), '', err)

    def __repr__(self) -> str:
        if self.err != QuoteResult.OK:
            return self.err.name
        base_asset, quote_asset = assets.assets_from_market(self.market)
        return f'{self.amountBaseAsset} {base_asset} for {self.amountQuoteAsset} {quote_asset}, fee: {self.feeQuoteAsset} {quote_asset}, fixed fee: {self.fixedFeeQuoteAsset} {quote_asset}'

@dataclass
class ExchBalance:
    symbol: str
    name: str
    total: Dec
    available: Dec

@dataclass
class ExchMarket:
    symbol: str
    base_asset: str
    quote_asset: str
    precision: int
    min_trade: Dec

@dataclass
class ExchOrderbookEntry:
    quantity: Dec
    rate: Dec

@dataclass
class ExchOrderbook:
    bids: list[ExchOrderbookEntry]
    asks: list[ExchOrderbookEntry]

@dataclass
class ExchOrder:
    id: Any
    base_asset: str
    quote_asset: str
    date: str
    side: assets.MarketSide
    status: str
    base_amount: Dec
    quote_amount: Dec
    base_amount_filled: Dec

#
# Interface
#

def _fixed_fee(market: str, broker_fee_fixed: dict[str, Dec]):
    base_asset, quote_asset = assets.assets_from_market(market)
    for key, value in broker_fee_fixed.items():
        if key == quote_asset:
            return value
    return Dec(0)

def _power(value: Dec, n: int):
    result = value
    while (n > 1):
        result = result * value
        n -= 1
    if n == 1:
        return result
    if n == 0:
        return Dec(1)
    assert False

def _roundAt(value: Dec, digit: int):
    return value.quantize(Dec(10) ** -digit)

class ExchInterface():

    def markets_data(self, use_cache: bool) -> list[ExchMarket] | None:
        raise Exception('to be overriden')

    def market_data(self, market: str, use_cache: bool) -> ExchMarket | None:
        raise Exception('to be overriden')

    def order_book_data(self, market: str, use_cache: bool) -> tuple[ExchOrderbook | None, Dec, dict[str, Dec]]:
        raise Exception('to be overriden')

    def bid_quote_amount(self, market: str, amount: Dec, use_cache=False) -> QuoteTotalPrice:
        assert isinstance(amount, Dec)
        dasset_market = self.market_data(market, use_cache=use_cache)
        if not dasset_market:
            return QuoteTotalPrice.error(QuoteResult.MARKET_API_FAIL)
        min_trade = Dec(dasset_market.min_trade)
        if amount < min_trade:
            return QuoteTotalPrice.error(QuoteResult.AMOUNT_TOO_LOW)

        order_book, broker_fee, broker_fee_fixed = self.order_book_data(market, use_cache=use_cache)
        if not order_book:
            return QuoteTotalPrice.error(QuoteResult.MARKET_API_FAIL)

        fixed_fee = _fixed_fee(market, broker_fee_fixed)
        filled = Dec(0)
        total_price = Dec(0)
        n = 0
        while amount > filled:
            if n >= len(order_book.asks):
                break
            rate = Dec(order_book.asks[n].rate)
            quantity = Dec(order_book.asks[n].quantity)
            quantity_to_use = quantity
            if quantity_to_use > amount - filled:
                quantity_to_use = amount - filled
            filled += quantity_to_use
            total_price += quantity_to_use * rate
            if filled == amount:
                total_price_including_margin = total_price * (Dec(1) + broker_fee / Dec(100))
                fee = total_price_including_margin - total_price
                return QuoteTotalPrice(amount, total_price_including_margin + fixed_fee, fee, fixed_fee, market, QuoteResult.OK)
            n += 1

        return QuoteTotalPrice.error(QuoteResult.INSUFFICIENT_LIQUIDITY)

    def bid_brute_force(self, market: str, quote_asset_amount: Dec, use_cache=False, log=False) -> QuoteTotalPrice:
        if log:
            logger.info('market: %s, quote_asset_amount: %s', market, quote_asset_amount)
        base_asset, quote_asset = assets.assets_from_market(market)
        smallest_amount = Dec(1) / _power(Dec(10), assets.asset_decimals(base_asset))
        # get starting amount
        dasset_market = self.market_data(market, use_cache=use_cache)
        if not dasset_market:
            return QuoteTotalPrice.error(QuoteResult.MARKET_API_FAIL)
        base_asset_amount = Dec(dasset_market.min_trade)
        # loop to find input that matches 'quote_asset_amount'
        n_rise = 0
        n_lower = 0
        n = 0
        while 1:
            quote = self.bid_quote_amount(market, base_asset_amount, use_cache)
            use_cache = True
            if quote.err != QuoteResult.OK:
                return quote
            quote_asset_rounded = _roundAt(quote.amountQuoteAsset, assets.asset_decimals(quote_asset))
            if log and n % 100 == 0:
                logger.info('n: %d, quote_asset_rounded: %s', n, quote_asset_rounded)
            n += 1
            if quote_asset_rounded < quote_asset_amount:
                base_asset_amount += smallest_amount * n_rise
                n_rise += 1
                n_lower = 0
            elif quote_asset_rounded > quote_asset_amount:
                base_asset_amount -= smallest_amount * n_lower
                n_rise = 0
                n_lower += 1
            else:
                return quote
        assert False

    def ask_quote_amount(self, market: str, amount: Dec, use_cache=False) -> QuoteTotalPrice:
        assert isinstance(amount, Dec)
        dasset_market = self.market_data(market, use_cache=use_cache)
        if not dasset_market:
            return QuoteTotalPrice.error(QuoteResult.MARKET_API_FAIL)
        min_trade = Dec(dasset_market.min_trade)
        if amount < min_trade:
            return QuoteTotalPrice.error(QuoteResult.AMOUNT_TOO_LOW)

        order_book, broker_fee, broker_fee_fixed = self.order_book_data(market, use_cache=use_cache)
        if not order_book:
            return QuoteTotalPrice.error(QuoteResult.MARKET_API_FAIL)

        fixed_fee = _fixed_fee(market, broker_fee_fixed)
        filled = Dec(0)
        total_price = Dec(0)
        n = 0
        while amount > filled:
            if n >= len(order_book.bids):
                break
            rate = Dec(order_book.bids[n].rate)
            quantity = Dec(order_book.bids[n].quantity)
            quantity_to_use = quantity
            if quantity_to_use > amount - filled:
                quantity_to_use = amount - filled
            filled += quantity_to_use
            total_price += quantity_to_use * rate
            if filled == amount:
                total_price_including_margin = total_price * (Dec(1) - broker_fee / Dec(100))
                fee = total_price - total_price_including_margin
                return QuoteTotalPrice(amount, total_price_including_margin - fixed_fee, fee, fixed_fee, market, QuoteResult.OK)
            n += 1

        return QuoteTotalPrice.error(QuoteResult.INSUFFICIENT_LIQUIDITY)

    def account_balances(self, asset: str | None = None, quiet=False) -> list[ExchBalance] | None:
        raise Exception('to be overriden')

    def order_create(self, market: str, side: assets.MarketSide, amount: Dec, price: Dec) -> str | None:
        raise Exception('to be overriden')

    def order_details(self, order_id: str, market: str) -> None | ExchOrder:
        raise Exception('to be overriden')

    def order_status_check(self, order_id: str, market: str) -> bool:
        order = self.order_details(order_id, market)
        if not order:
            return False
        return order.base_amount == order.base_amount_filled

    def funds_available_us(self, asset: str, amount: Dec):
        assert isinstance(amount, Dec)
        balances = self.account_balances(asset)
        if balances:
            for balance in balances:
                if balance.symbol == asset:
                    return balance.available >= amount
        return False

    def markets_refresh_cache(self, margin: int):
        raise Exception('to be overriden')

    def order_book_refresh_cache(self, margin: int):
        raise Exception('to be overriden')
