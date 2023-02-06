import logging
import uuid
from dataclasses import dataclass
import json

import marshmallow
import marshmallow_dataclass

from app_core import app
from log_utils import setup_logging
from web_utils import create_hmac_sig
import httpreq

logger = logging.getLogger(__name__)

API_KEY = app.config['POUCH_API_KEY']
API_SECRET = app.config['POUCH_API_SECRET']
URL_BASE = 'https://remit.pouch.ph/api/v1/'
if app.config['TESTNET']:
    URL_BASE = 'https://remit-sandbox.pouch.ph/v1/'

WEBHOOK_INVOICE_PAID = 'invoice.paid'
WEBHOOK_INVOICE_FAILED = 'invoice.failed'

class CamelcaseSchema(marshmallow.Schema):
    """A Schema that marshals data with *camelCased* keys from *snake_cased*."""
    def on_bind_field(self, field_name, field_obj):
        field_name = field_obj.data_key or field_name
        camel_cased = field_name[0] + field_name.title().replace('_', '')[1:]
        field_obj.data_key = camel_cased

@dataclass
class PouchPaymentMethod:
    code: str
    name: str

@dataclass
class PouchRecipient:
    name: str
    account_number: str | None
    mobile_number: str | None

@dataclass
class PouchInvoiceReq:
    reference_id: str
    description: str
    payment_method_code: str
    currency: str
    amount: int
    recipient: PouchRecipient

@dataclass
class PouchFee:
    amount: int
    currency: str

@dataclass
class PouchInvoice:
    ref_id: str
    status: str
    bolt11: str
    sender_amount: int
    sender_currency: str
    recipient_name: str
    recipient_account_number: str | None
    recipient_mobile_number: str | None
    recipient_amount: int
    recipient_currency: str
    rates: dict[str, dict[str, float]]
    fees: dict[str, PouchFee]
    created_at: str
    updated_at: str

def _req(endpoint, data=None, quiet=False, use_put=False):
    url = URL_BASE + endpoint
    headers = {'X-Pouch-Api-Key': API_KEY}
    if data:
        data = json.dumps(data)
        if not quiet:
            logger.info('   POST - %s', url)
            #logger.info('          %s', data)
        headers['X-Pouch-Signature'] = create_hmac_sig(API_SECRET, data, 'hex')
        headers['Content-Type'] = 'application/json'
        if use_put:
            return httpreq.put(url, headers=headers, data=data)
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

def _parse_invoice(json):
    data = json['data']
    ref_id = data['referenceId']
    status = data['status']
    bolt11 = data['bolt11']
    sender_amount = data['senderDetails']['amount']
    sender_currency = data['senderDetails']['currency']
    recipient_name = data['recipientDetails']['name']
    recipient_account_number = data['recipientDetails']['accountNumber'] if 'accountNumber' in data['recipientDetails'] else None
    recipient_mobile_number = data['recipientDetails']['mobileNumber'] if 'mobileNumber' in data['recipientDetails'] else None
    recipient_amount = data['recipientDetails']['amount']
    recipient_currency = data['recipientDetails']['currency']
    rates = {}
    for name, value in data['rates'].items():
        rates[name] = value
    fees = {}
    for name, value in data['fees'].items():
        fees[name] = PouchFee(value['amount'], value['currency'])
    created_at = data['createdAt']
    updated_at = data['updatedAt']
    return PouchInvoice(ref_id, status, bolt11, sender_amount, sender_currency, recipient_name, recipient_account_number, recipient_mobile_number, recipient_amount, recipient_currency, rates, fees, created_at, updated_at)

def payment_methods(quiet=False) -> dict[str, list[PouchPaymentMethod]]:
    if not quiet:
        logger.info(':: calling payment methods..')
    r = _req('paymentMethods', quiet=quiet)
    _check_response_status(r)
    payment_methods = {}
    categories = r.json()['data']['results']
    for name, value in categories.items():
        payment_methods[name] = []
        for pm in value:
            payment_methods[name].append(PouchPaymentMethod(pm['code'], pm['name']))
    return payment_methods

def invoice_create(invoice_req: PouchInvoiceReq, quiet=False) -> PouchInvoice | None:
    if not quiet:
        logger.info(':: calling invoice create..')
    Schema = marshmallow_dataclass.class_schema(PouchInvoiceReq, base_schema=CamelcaseSchema)
    r = _req('invoices', Schema().dump(invoice_req), quiet=quiet)
    _check_response_status(r)
    return _parse_invoice(r.json())

def invoice_check(ref_id: str, quiet=False) -> PouchInvoice | None:
    if not quiet:
        logger.info(':: calling invoice check..')
    r = _req(f'invoices/{ref_id}', quiet=quiet)
    _check_response_status(r)
    return _parse_invoice(r.json())

def webhook_set(event: str, url: str, quiet=False):

    #
    # TODO: test webhooks
    #

    if not quiet:
        logger.info(':: calling webhook set..')
    r = _req('webhooks', dict(event=event, url=url), use_put=True, quiet=quiet)
    _check_response_status(r)
    return True

def webhook_get(quiet=False):
    if not quiet:
        logger.info(':: calling webhooks get..')
    r = _req('webhooks', quiet=quiet)
    _check_response_status(r)
    return r.json()['data']

if __name__ == '__main__':
    setup_logging(logger, logging.DEBUG)

    #print(payment_methods())
    #print(invoice_create(PouchInvoiceReq(str(uuid.uuid4()), 'test invoice', 'UNODPHM2XXX', 'SAT', 500, PouchRecipient('Dan Test', '1234567', None))))
    #print(invoice_check('9aadfbf8-23e1-46e2-9f95-61d9e55ebb54'))

    print(webhook_set(WEBHOOK_INVOICE_PAID, 'https://www.example.com'))
    print(webhook_get())
