from dataclasses import dataclass
import logging
from decimal import Decimal as Dec
import json
from app_core import app
import assets
import utils
import exch
from exch import BROKER_ORDER_FEE, BROKER_ORDER_FEE_FIXED

logger = logging.getLogger(__name__)

#
# Mock Exchange
#

class ExchMock(exch.ExchInterface):

    def markets_data(self, use_cache: bool) -> list[exch.ExchMarket] | None:
        markets = []
        for key in assets.MARKETS:
            markets.append(self.market_data(key, use_cache))
        return markets

    def market_data(self, market: str, use_cache: bool) -> exch.ExchMarket | None:
        base_asset, quote_asset = assets.assets_from_market(market)
        return exch.ExchMarket(market, base_asset, quote_asset, 8, Dec('0.000001'))

    def order_book_data(self, market: str, use_cache: bool) -> tuple[exch.ExchOrderbook | None, Dec, dict[str, Dec]]:
        bids = [exch.ExchOrderbookEntry(quantity=Dec(1), rate=Dec(9999)),
                exch.ExchOrderbookEntry(quantity=Dec(1), rate=Dec(9950)),
                exch.ExchOrderbookEntry(quantity=Dec(1), rate=Dec(9925)),
                exch.ExchOrderbookEntry(quantity=Dec(1), rate=Dec(9900))]
        asks = [exch.ExchOrderbookEntry(quantity=Dec(1), rate=Dec(10000)),
                exch.ExchOrderbookEntry(quantity=Dec(1), rate=Dec(10050)),
                exch.ExchOrderbookEntry(quantity=Dec(1), rate=Dec(10075)),
                exch.ExchOrderbookEntry(quantity=Dec(1), rate=Dec(10100))]
        return exch.ExchOrderbook(bids, asks), BROKER_ORDER_FEE, BROKER_ORDER_FEE_FIXED

    def account_balances(self, asset: str | None = None, quiet=False) -> list[exch.ExchBalance] | None:
        balances = []
        for item in assets.ASSETS.values():
            balance = exch.ExchBalance(symbol=item.symbol, name=item.name, total=Dec('9999.01234567890123456789'), available=Dec('9999.01234567890123456789'))
            balances.append(balance)
        return balances

    def order_create(self, market: str, side: assets.MarketSide, amount: Dec, price: Dec) -> str | None:
        return utils.generate_key()

    def order_details(self, order_id: str, market: str) -> None | exch.ExchOrder:
        return exch.ExchOrder(id=order_id, status='Completed', base_asset='', quote_asset='', date='', side=assets.MarketSide.ASK, base_amount=Dec(1), quote_amount=Dec(1), base_amount_filled=Dec(1))

    def markets_refresh_cache(self, margin: int):
        return

    def order_book_refresh_cache(self, margin: int):
        return
