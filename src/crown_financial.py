import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm.session import Session

from app_core import app
from models import FiatDepositCode
from log_utils import setup_logging
import httpreq

logger = logging.getLogger(__name__)

EMAIL = app.config['CROWN_ACCOUNT_EMAIL']
API_KEY = app.config['CROWN_API_KEY']
API_SECRET = app.config['CROWN_API_SECRET']
CROWN_ACCOUNT_CODE = app.config['CROWN_ACCOUNT_CODE']
CROWN_WITHDRAW_FEE_INT = int(app.config['CROWN_WITHDRAW_FEE_INT'])
CROWN_WITHDRAW_NAME = app.config['CROWN_WITHDRAW_NAME']
URL_BASE = 'https://api.crownmoney.online/'
if app.config['TESTNET']:
    URL_BASE = 'https://api.mycrown.services/'

CURRENCY = 'NZD'

@dataclass
class CrownTx:
    TYPE_WITHDRAWAL = 'Withdrawal'
    TYPE_DEPOSIT = 'Deposit'

    STATUS_PENDING = 'pending'
    STATUS_ACCEPTED = 'accepted'
    STATUS_REJECTED = 'rejected'
    STATUS_FROZEN = 'frozen'
    STATUS_REQUIRE_AML_DOC = 'require_aml_document'
    STATUS_CLARITY_AROUND_NAME_MISMATCH = 'clarity_around_name_mismatch'

    crown_txn_id: str
    currency: str
    amount: int
    fee: int
    date: str
    user_reference: str
    status: str
    type: str

def _parse_tx(json_tx):
    amount = int(json_tx['transaction_amount'] * 100)
    fee = int(json_tx['transaction_transaction_fee'] * 100)
    reference = json_tx['transaction_info']['user_reference']
    return CrownTx(json_tx['transaction_id'], json_tx['transaction_currency'], amount, fee, json_tx['transaction_date'], reference, json_tx['transaction_status'], json_tx['transaction_type'])

def _req(endpoint, data=None, quiet=False):
    url = URL_BASE + endpoint
    authorizing_key = base64.b64encode(f'{EMAIL}:{API_SECRET}'.encode('utf-8')).decode()
    headers = {'Authorization': f'Basic {authorizing_key}', 'APIKEY': f'{API_KEY}'}
    if data:
        if not quiet:
            logger.info('   POST - %s', url)
        return httpreq.post(url, headers=headers, data=data)
    if not quiet:
        logger.info('   GET - %s', url)
    return httpreq.get(url, headers=headers)

def _check_response_status(req: httpreq.Response):
    try:
        req.raise_for_status()
    except Exception as e:
        logger.error('%d - %s', req.status_code, req.url)
        logger.error(req.text)
        raise e
    jsn = req.json()
    if not jsn['status'] and jsn['msg']:
        logger.error('failure message: %s', jsn['msg'])
        raise Exception()

def code_from_deposit(db_session: Session, txn: CrownTx) -> FiatDepositCode | None:
    parts = txn.user_reference.split('-')
    for part in parts:
        part = part.strip().upper()
        if part == CROWN_ACCOUNT_CODE:
            continue
        code = FiatDepositCode.from_token(db_session, part)
        if code:
            return code
    return None

def balance_float(quiet=False) -> float:
    if not quiet:
        logger.info(':: calling balance..')
    r = _req('balance', {}, quiet=quiet)
    _check_response_status(r)
    return r.json()['value'][CURRENCY]

def balance(quiet=False):
    return int(balance_float(quiet=quiet) * 100)

def transaction_details(crown_txn_id: str):
    logger.info(':: calling transaction details id..')
    r = _req(f'transaction/details/{crown_txn_id}', {})
    _check_response_status(r)
    return _parse_tx(r.json()['value'])

def transactions() -> list[CrownTx]:
    logger.info(':: calling transaction..')
    r = _req('transaction/all', {})
    _check_response_status(r)
    txs = []
    for json_tx in r.json()['value']:
        txs.append(_parse_tx(json_tx))
    return txs

def _dt_format(date: datetime):
    return f'{date.month}-{date.day}-{date.year}'

def transactions_filtered_status(status: str, from_date: datetime, to_date: datetime) -> list[CrownTx]:
    logger.info(':: calling transaction filtered status..')
    # status (string) - available parameters ('pending', 'accepted', 'rejected', 'frozen', 'require_aml_document', 'clarity_around_name_mismatch')
    # dates (string) - '%m-%d-%Y'
    r = _req(f'transaction/filtered/status/{status}/from/{_dt_format(from_date)}/to/{_dt_format(to_date)}', {})
    _check_response_status(r)
    txs = []
    for json_tx in r.json()['value']:
        txs.append(_parse_tx(json_tx))
    return txs

def transactions_filtered_type(type_: str, from_date: datetime, to_date: datetime) -> list[CrownTx]:
    logger.info(':: calling transaction filtered type..')
    # type (string) - available parameters ('deposit', 'withdrawal')
    # dates (string) - '%m-%d-%Y'
    r = _req(f'transaction/filtered/type/{type_.lower()}/from/{_dt_format(from_date)}/to/{_dt_format(to_date)}', {})
    _check_response_status(r)
    txs = []
    for json_tx in r.json()['value']:
        txs.append(_parse_tx(json_tx))
    return txs

def withdrawal(amount: int, reference: str, code: str, account_number: str, account_name: str, account_address_01: str, account_address_02: str, account_address_country: str) -> str:
    logger.info(':: calling withdrawal to bank..')
    amount_float = amount / 100.0
    r = _req('transaction/withdrawal/bank', dict(source_currency=CURRENCY, to_currency=CURRENCY, amount=amount_float, pre_assigned_code=reference, reference=code,
                                                 sent_payment_to_country='New Zealand', to_account_number=account_number, bank_swift_bic='-', bank_account_name=account_name,
                                                 bank_owner_address_1=account_address_01, bank_owner_address_2=account_address_02, bank_owner_address_country=account_address_country))
    _check_response_status(r)
    return r.json()['transaction_id']

if __name__ == '__main__':
    setup_logging(logger, logging.DEBUG)
    for tx in transactions_filtered_type(CrownTx.TYPE_DEPOSIT, datetime.now() - timedelta(days=7), datetime.now()):
        print(tx)
