import logging
import uuid
from dataclasses import dataclass
import json
from datetime import datetime

import marshmallow
import marshmallow_dataclass

from app_core import app
from log_utils import setup_logging
from web_utils import create_hmac_sig
import httpreq

logger = logging.getLogger(__name__)

PROVIDER = 'pouch'
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
class PouchError:
    code: str
    message: str
    details: list[str]

@dataclass
class PouchPaymentMethod:
    code: str
    name: str

@dataclass
class PouchPaymentMethodsResult:
    methods: dict[str, list[PouchPaymentMethod]] | None
    err: PouchError | None

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

    def __init__(self, desc: str, paycode: str, currency: str, amount: int, recipient: PouchRecipient):
        self.reference_id = str(uuid.uuid4())
        self.description = desc
        self.payment_method_code = paycode
        self.currency = currency
        self.amount = amount
        self.recipient = recipient

@dataclass
class PouchAmount:
    amount: int
    currency: str

@dataclass
class PouchRecipientAmount(PouchRecipient, PouchAmount):
    pass

@dataclass
class PouchInvoice:
    ref_id: str
    status: str
    bolt11: str
    sender: PouchAmount
    recipient: PouchRecipientAmount
    rates: dict[str, dict[str, float]]
    fees: dict[str, PouchAmount]
    created_at: datetime
    updated_at: datetime

    def to_json(self):
        Schema = marshmallow_dataclass.class_schema(PouchInvoice)
        return Schema().dump(self)

@dataclass
class PouchInvoiceResult:
    invoice: PouchInvoice | None
    err: PouchError | None

@dataclass
class PouchWebhooksResult:
    webhooks: dict[str, str] | None
    err: PouchError | None

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

def _check_response_status(req: httpreq.Response) -> PouchError | None:
    try:
        req.raise_for_status()
    except Exception:
        logger.error('%d - %s', req.status_code, req.url)
        logger.error(req.text)
        try:
            err = req.json()['error']
            return PouchError(err['code'], err['message'], err['details'])
        except Exception:
            return PouchError('', f'{req.status_code} - {req.url}', [])
    return None

def _parse_invoice(json):
    data = json['data']
    ref_id = data['referenceId']
    status = data['status']
    bolt11 = data['bolt11']
    sd = data['senderDetails']
    sender = PouchAmount(sd['amount'], sd['currency'])
    rd = data['recipientDetails']
    recipient_name = rd['name']
    recipient_account_number = rd['accountNumber'] if 'accountNumber' in rd else None
    recipient_mobile_number = rd['mobileNumber'] if 'mobileNumber' in rd else None
    recipient_amount = rd['amount']
    recipient_currency = rd['currency']
    recipient = PouchRecipientAmount(recipient_amount, recipient_currency, recipient_name, recipient_account_number, recipient_mobile_number)
    rates = {}
    for name, value in data['rates'].items():
        rates[name] = value
    fees = {}
    for name, value in data['fees'].items():
        fees[name] = PouchAmount(value['amount'], value['currency'])
    created_at = datetime.strptime(data['createdAt'], "%Y-%m-%dT%H:%M:%S.%f%z")
    updated_at = datetime.strptime(data['updatedAt'], "%Y-%m-%dT%H:%M:%S.%f%z")
    return PouchInvoice(ref_id, status, bolt11, sender, recipient, rates, fees, created_at, updated_at)

def payment_methods(quiet=False) -> PouchPaymentMethodsResult:
    if not quiet:
        logger.info(':: calling payment methods..')
    r = _req('paymentMethods', quiet=quiet)
    err = _check_response_status(r)
    if err:
        return PouchPaymentMethodsResult(None, err)
    payment_methods = {}
    categories = r.json()['data']['results']
    for name, value in categories.items():
        payment_methods[name] = []
        for pm in value:
            payment_methods[name].append(PouchPaymentMethod(pm['code'], pm['name']))
    return PouchPaymentMethodsResult(payment_methods, None)

def invoice_create(invoice_req: PouchInvoiceReq, quiet=False) -> PouchInvoiceResult:
    if not quiet:
        logger.info(':: calling invoice create..')
    Schema = marshmallow_dataclass.class_schema(PouchInvoiceReq, base_schema=CamelcaseSchema)
    r = _req('invoices', Schema().dump(invoice_req), quiet=quiet)
    err = _check_response_status(r)
    if err:
        return PouchInvoiceResult(None, err)
    return PouchInvoiceResult(_parse_invoice(r.json()), None)

def invoice_status(ref_id: str, quiet=False) -> PouchInvoiceResult:
    if not quiet:
        logger.info(':: calling invoice status..')
    r = _req(f'invoices/{ref_id}', quiet=quiet)
    err = _check_response_status(r)
    if err:
        return PouchInvoiceResult(None, err)
    return PouchInvoiceResult(_parse_invoice(r.json()), None)

def webhook_set(event: str, url: str, quiet=False) -> PouchError | None:

    #
    # TODO: test webhooks
    #

    if not quiet:
        logger.info(':: calling webhook set..')
    r = _req('webhooks', dict(event=event, url=url), use_put=True, quiet=quiet)
    err = _check_response_status(r)
    if err:
        return err
    return None

def webhook_get(quiet=False) -> PouchWebhooksResult:
    if not quiet:
        logger.info(':: calling webhooks get..')
    r = _req('webhooks', quiet=quiet)
    err = _check_response_status(r)
    if err:
        return PouchWebhooksResult(None, err)
    return PouchWebhooksResult(r.json()['data'], None)

if __name__ == '__main__':
    setup_logging(logger, logging.DEBUG)

    #print(payment_methods())
    #print(invoice_create(PouchInvoiceReq('test invoice', 'UNODPHM2XXX', 'SAT', 500, PouchRecipient('Dan Test', '1234567', None))))
    #print(invoice_status('9aadfbf8-23e1-46e2-9f95-61d9e55ebb54'))

    print(webhook_set(WEBHOOK_INVOICE_PAID, 'https://www.example.com'))
    print(webhook_get())
