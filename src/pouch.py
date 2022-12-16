import logging
from dataclasses import dataclass

from app_core import app
from log_utils import setup_logging
import httpreq

logger = logging.getLogger(__name__)

API_KEY = app.config['POUCH_API_KEY']
URL_BASE = 'https://app.pouch.ph/api/v2/remit/'
if app.config['TESTNET']:
    URL_BASE = 'https://test.pouch.ph/api/v2/remit/'

@dataclass
class PouchBank:
    code: str
    name: str
    brstn: str | None

@dataclass
class PouchSender:
    fee_centavos: int
    bolt11: str

@dataclass
class PouchRecipient:
    method: str
    name: str
    account_number: str
    bank_code: str

@dataclass
class PouchOrder:
    id: str
    ref_id: str
    partner: str
    amount_centavos: int
    sender: PouchSender
    recipient: PouchRecipient
    status: str
    created_at: str
    updated_at: str

def _req(endpoint, data=None, quiet=False):
    url = URL_BASE + endpoint
    headers = {'x-api-key': API_KEY}
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

def _parse_order(json):
    sender = json['senderDetails']
    recipient = json['recipientDetails']
    return PouchOrder(json['_id'], json['referenceId'], json['partner'], json['amountInCentavos'], PouchSender(sender['feeInCentavos'], sender['bolt11']), PouchRecipient(recipient['method'], recipient['name'], recipient['accountNumber'], recipient['bankCode']), json['status'], json['createdAt'], json['updatedAt'])


def rates(quiet=False) -> dict[str, str]:
    if not quiet:
        logger.info(':: calling rates..')
    r = _req('rates', quiet=quiet)
    _check_response_status(r)
    return r.json()

def banks(quiet=False) -> list[PouchBank]:
    if not quiet:
        logger.info(':: calling banks..')
    r = _req('banks', quiet=quiet)
    _check_response_status(r)
    banks = []
    for b in r.json():
        banks.append(PouchBank(b['bankCode'], b['bankName'], b['brstn'] if 'brstn' in b else None))
    return banks

def remit(bank_code: str, amount_centavos: int, name: str, account_number: str, quiet=False):
    if not quiet:
        logger.info(':: calling remit..')
    r = _req('', dict(bankCode=bank_code, amountInCentavos=amount_centavos, name=name, accountNumber=account_number), quiet=quiet)
    _check_response_status(r)
    return _parse_order(r.json())

def check_transfer(ref_id: str, quiet=False):
    if not quiet:
        logger.info(':: calling check order..')
    r = _req(ref_id, quiet=quiet)
    _check_response_status(r)
    return _parse_order(r.json())

def retry(ref_id: str, bank_code: str, amount_centavos: int, name: str, account_number: str, quiet=False):
    if not quiet:
        logger.info(':: calling retry..')
    r = _req('retry', dict(referenceId=ref_id, bankCode=bank_code, amountInCentavos=amount_centavos, name=name, accountNumber=account_number), quiet=quiet)
    _check_response_status(r)
    return _parse_order(r.json())

def refund(ref_id: str, invoice: str, quiet=False):
    if not quiet:
        logger.info(':: calling refund..')
    r = _req('refund', dict(referenceId=ref_id, pr=invoice), quiet=quiet)
    _check_response_status(r)
    return _parse_order(r.json())

if __name__ == '__main__':
    setup_logging(logger, logging.DEBUG)
    print(rates())
    #banks = banks()
    #print(banks[0])
    #print(banks[-1])
    #print(remit('AIIPPHM1XXX', 500, 'Satoshi Nakamoto', '012345'))
    print(check_transfer('e4b14ff0-470f-44b1-847d-15ede6320dee'))
