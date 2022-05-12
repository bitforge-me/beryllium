import os
from decimal import Decimal
from typing import Optional
import logging
from pyln.client.lightning import RpcError
from bitcoin.rpc import Proxy
import requests

from app_core import app, db
import assets
from ln import LnRpc
from models import BtcTxIndex

logger = logging.getLogger(__name__)
TESTNET = app.config['TESTNET']

def _build_bitcoin_rpc_url(bitcoin_datadir, bitcoin_host):
    btc_conf_file = os.path.join(bitcoin_datadir, 'bitcoin.conf')
    conf = {'rpcuser': ""}
    with open(btc_conf_file, 'r', encoding='utf-8') as fd:
        for line in fd.readlines():
            if '#' in line:
                line = line[:line.index('#')]
            if '=' not in line:
                continue
            k, v = line.split('=', 1)
            conf[k.strip()] = v.strip()
    authpair = f"{conf['rpcuser']}:{conf['rpcpassword']}"
    service_url = f"http://{authpair}@{bitcoin_host}:{conf['rpcport']}"
    return service_url

def bitcoind_service_url():
    return _build_bitcoin_rpc_url(app.config['BITCOIN_DATADIR'], app.config['BITCOIN_RPCCONNECT'])

def bitcoind_rpc_url(service_url, name, *args):
    bitcoind = Proxy(service_url=service_url)
    return bitcoind._call(name, *args) # pylint: disable=protected-access

def bitcoind_rpc(name, *args):
    service_url = bitcoind_service_url()
    return bitcoind_rpc_url(service_url, name, *args)

def _is_ln(asset: str, l2_network: Optional[str]) -> bool:
    return asset == assets.BTC.symbol and l2_network == assets.BTCLN.symbol

def incoming_available(asset: str, l2_network: Optional[str], amount_dec: Decimal) -> bool:
    if not _is_ln(asset, l2_network):
        return False
    rpc = LnRpc()
    funds = rpc.list_funds()
    sats = assets.asset_dec_to_int(asset, amount_dec)
    logger.info('required: %d sats, largest channel theirs: %d sats', sats, funds['sats_largest_channel_theirs'])
    return funds['sats_largest_channel_theirs'] >= sats

def funds_available(asset: str, l2_network: Optional[str], amount_dec: Decimal) -> bool:
    if not _is_ln(asset, l2_network):
        return False
    rpc = LnRpc()
    funds = rpc.list_funds()
    sats = assets.asset_dec_to_int(asset, amount_dec * Decimal('1.01')) # add a 1% buffer for fees
    logger.info('required: %d sats, largest channel: %d sats', sats, funds['sats_largest_channel'])
    return funds['sats_largest_channel'] >= sats

def withdrawals_supported(asset: str, l2_network: Optional[str]):
    return _is_ln(asset, l2_network)

def withdrawal_create(asset: str, l2_network: Optional[str], amount_dec: Decimal, recipient: str):
    assert withdrawals_supported(asset, l2_network)
    rpc = LnRpc()
    try:
        result = rpc.decode_bolt11(recipient)
        amount_sat = assets.asset_dec_to_int(asset, amount_dec)
        if amount_sat != result['amount_sat']:
            logger.error('ln pay amount does not match: %d, %d', amount_sat, result['amount_sat'])
            return None, 'pay amount does not match'
        result = rpc.pay(recipient)
        if not result:
            logger.error('ln pay failed: %s', recipient)
            return None, 'pay failed'
        logger.info('ln pay made: %s', result['payment_hash'])
        return result['payment_hash'], None
    except RpcError as e:
        logger.error('ln pay error: %s', e.error)
        return None, e.error

def withdrawal_completed(wallet_reference: str) -> bool:
    rpc = LnRpc()
    result = rpc.pay_status_from_hash(wallet_reference)
    if not result and len(result['pays']) != 1:
        logger.error('ln pay not found: %s', wallet_reference)
        return False
    pay = result['pays'][0]
    complete = pay['status'] == 'complete'
    return complete

def deposits_supported(asset: str, l2_network: Optional[str]):
    return _is_ln(asset, l2_network)

def deposit_create(asset: str, l2_network: Optional[str], label: str, msg: str, amount_dec: Decimal):
    assert deposits_supported(asset, l2_network)
    sats = assets.asset_dec_to_int(asset, amount_dec)
    rpc = LnRpc()
    try:
        invoice = rpc.invoice(sats, label, msg)
        if not invoice:
            logger.error('ln invoice failed: %s %s', amount_dec, asset)
            return None, 'invoice failed'
        logger.info('ln invoice made: %s', invoice)
        return invoice['bolt11'], None
    except RpcError as e:
        logger.error('ln invoice error: %s', e.error)
        return None, e.error

def deposit_expired(bolt11: str) -> bool:
    rpc = LnRpc()
    result = rpc.invoice_status(bolt11)
    if not result and len(result['invoices']) != 1:
        logger.error('ln invoice not found: %s', bolt11)
        return False
    invoice = result['invoices'][0]
    expired = invoice['status'] == 'expired'
    return expired

def deposit_completed(bolt11: str) -> bool:
    rpc = LnRpc()
    result = rpc.invoice_status(bolt11)
    if not result and len(result['invoices']) != 1:
        logger.error('ln invoice not found: %s', bolt11)
        return False
    invoice = result['invoices'][0]
    complete = invoice['status'] == 'paid'
    return complete

def any_deposit_completed(lastpay_index):
    rpc = LnRpc()
    try:
        return rpc.wait_any_invoice(lastpay_index, 0), None
    except RpcError as e:
        return None, e.error

def btc_transactions_index():
    MAX_BLOCK_HISTORY = 128 * 30 # one month
    service_url = bitcoind_service_url()
    rpc = LnRpc()
    try:
        txs = rpc.list_txs()['transactions']
        for tx in txs:
            for input in tx["inputs"]:
                input_txid = input['txid']
                input_tx = BtcTxIndex.from_txid(db.session, input_txid)
                blockheight = 0
                if not input_tx:
                    logger.info('searching for input tx %s', input_txid)
                    # try mempool
                    # pylint: disable=broad-except
                    try:
                        input_tx = bitcoind_rpc_url(service_url, 'getrawtransaction', input_txid, True)
                    except:
                        pass
                    if not input_tx:
                        # try looping back though blocks
                        block_count = bitcoind_rpc_url(service_url, 'getblockcount')
                        current_block = block_count
                        while current_block + MAX_BLOCK_HISTORY > block_count and current_block > 0:
                            blockhash = bitcoind_rpc_url(service_url, 'getblockhash', current_block)
                            # pylint: disable=broad-except
                            try:
                                input_tx = bitcoind_rpc_url(service_url, 'getrawtransaction', input_txid, True, blockhash)
                            except:
                                pass
                            if input_tx:
                                logger.info('found input tx in block %s', current_block)
                                blockheight = current_block
                                break
                            current_block -= 1
                    if input_tx:
                        input_tx = BtcTxIndex(input_txid, input_tx['hex'], blockheight, input_tx['blockhash'])
                    else:
                        logger.error('failed to find input tx after searching top %d blocks, trying bitaps.com', MAX_BLOCK_HISTORY)

                        network = 'v1'
                        if TESTNET:
                            network = 'testnet/v1'
                        # pylint: disable=broad-except
                        try:
                            tx = requests.get(f'https://api.bitaps.com/btc/{network}/blockchain/transaction/{input_txid}').json()
                            blockhash = tx['data']['blockHash']
                            input_tx = bitcoind_rpc_url(service_url, 'getrawtransaction', input_txid, True, blockhash)
                        except:
                            pass
                        if not input_tx:
                            logger.error('failed to find input tx after searching bitaps.com', MAX_BLOCK_HISTORY)
                            continue
                    # make db input tx
                    input_tx = BtcTxIndex(input_txid, input_tx['hex'], blockheight, input_tx['blockhash'])
                    db.session.add(input_tx)
                    db.session.commit()
    except RpcError as e:
        logger.error('btc transactions index failed: %s', e.error)

def btc_input_transaction_get(txid: str):
    tx = BtcTxIndex.from_txid(db.session, txid)
    if tx:
        return tx.hex
    return None