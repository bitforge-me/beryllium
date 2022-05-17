import hmac
import hashlib
import base64
import logging
from typing import Optional, Union

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.scoping import scoped_session
from flask import jsonify, request
from flask.wrappers import Response

from models import ApiKey

logger = logging.getLogger(__name__)

AUTH_FAILED = 'authentication failed'
OLD_NONCE = 'old nonce'
INVALID_JSON = 'invalid json'
INVALID_EMAIL = 'invalid email'
EMPTY_PASSWORD = 'empty password'
PHOTO_DATA_LARGE = 'photo data too large'
NOT_FOUND = 'not found'
NOT_CREATED = 'not created'
LIMIT_TOO_LARGE = 'limit too large'
INVALID_TX = 'invalid tx'
UNAUTHORIZED = 'unauthorized'
INVALID_CATEGORY = 'invalid category'
USER_EXISTS = 'user exists'
INCORRECT_PASSWORD = 'incorrect password'
WEAK_PASSWORD = 'weak password'
NOT_IMPLEMENTED  = 'net yet implemented'
NOT_AVAILABLE = 'not available'
INVALID_AMOUNT = 'invalid amount'
INVALID_MARKET = 'invalid market'
INVALID_ASSET = 'invalid asset'
INVALID_NETWORK = 'invalid network'
INVALID_SIDE = 'invalid side'
INSUFFICIENT_LIQUIDITY = 'insufficient liquidity'
INSUFFICIENT_BALANCE = 'insufficient balance'
AMOUNT_TOO_LOW = 'amount too low'
INVALID_RECIPIENT = 'invalid recipient'
EXPIRED = 'expired'
INVALID_STATUS = 'invalid status'
FAILED_PAYMENT_CREATE = 'payment creation failed'
FAILED_EXCHANGE = 'exchange operation failed'
FAILED_WALLET = 'wallet operation failed'
KYC_REQUEST_EXISTS = 'user verification request exists'
KYC_REQUEST_NOT_EXISTS = 'user verification request does not exist'
KYC_SEND_MOBILE_FAILED = 'user verification SMS failed'
KYC_NOT_VALIDATED = 'user not verified'
INVALID_PARAMETER = 'invalid parameter'
FAILED_CODE_SEND = 'failed code send'
TWO_FACTOR_ENABLED = 'two factor enabled'
TWO_FACTOR_DISABLED = 'two factor disabled'
UNKNOWN_ERROR = 'unknown error'

def bad_request(message: str, code: int = 400) -> Response:
    logger.warning(message)
    response = jsonify({'message': message})
    response.status_code = code
    return response

def get_json_params(json_content, param_names: list[str]) -> tuple[list, Optional[Response]]:
    param_values = []
    param_name = ''
    try:
        for param in param_names:
            param_name = param
            param_values.append(json_content[param])
    except Exception as e: # pylint: disable=broad-except
        logger.error("'%s' not found", param_name)
        logger.error(e)
        return param_values, bad_request(f"'{param_name}' not found")
    return param_values, None

def get_json_params_optional(json_content, param_names: list[str]) -> list:
    param_values = []
    for param in param_names:
        try:
            param_values.append(json_content[param])
        except Exception: # pylint: disable=broad-except
            param_values.append(None)
    return param_values

def to_bytes(data: Union[str, bytes, bytearray]) -> Union[bytes, bytearray]:
    if not isinstance(data, (bytes, bytearray)):
        return data.encode("utf-8")
    return data

def create_hmac_sig(api_secret: str, message: str) -> str:
    _hmac = hmac.new(to_bytes(api_secret), msg=to_bytes(message), digestmod=hashlib.sha256)
    signature = _hmac.digest()
    signature = base64.b64encode(signature).decode("utf-8")
    return signature

def request_get_signature() -> str:
    return request.headers.get('X-Signature')

def check_hmac_auth(api_key: ApiKey, nonce: int, sig: str, body: str) -> tuple[bool, str]:
    if int(nonce) <= int(api_key.nonce):
        return False, OLD_NONCE
    our_sig = create_hmac_sig(api_key.secret, body)
    if sig == our_sig:
        api_key.nonce = nonce
        return True, ""
    return False, AUTH_FAILED

def check_auth(session: scoped_session, api_key_token: str, nonce: int, sig: str, body: str) -> tuple[bool, str, Optional[ApiKey]]:
    # pylint: disable=import-outside-toplevel
    api_key = ApiKey.from_token(session, api_key_token)
    if not api_key:
        return False, AUTH_FAILED, None
    if not api_key.user.active:
        return False, AUTH_FAILED, None
    res, reason = check_hmac_auth(api_key, nonce, sig, body)
    if not res:
        return False, reason, None
    # update api key nonce
    session.commit()
    return True, "", api_key

# pylint: disable=unbalanced-tuple-unpacking
# pylint: disable=invalid-name
def auth_request(db: SQLAlchemy) -> tuple[Optional[ApiKey], Optional[Response]]:
    sig = request_get_signature()
    content = request.get_json(force=True)
    if content is None:
        return None, bad_request(INVALID_JSON)
    params, err_response = get_json_params(content, ["api_key", "nonce"])
    if err_response:
        return None, err_response
    api_key, nonce = params
    res, reason, api_key = check_auth(db.session, api_key, nonce, sig, request.data)
    if not res:
        return None, bad_request(reason)
    return api_key, None

# pylint: disable=unbalanced-tuple-unpacking
# pylint: disable=invalid-name
def auth_request_get_single_param(db: SQLAlchemy, param_name: str) -> tuple[Optional[str], Optional[ApiKey], Optional[Response]]:
    sig = request_get_signature()
    content = request.get_json(force=True)
    if content is None:
        return None, None, bad_request(INVALID_JSON)
    params, err_response = get_json_params(content, ["api_key", "nonce", param_name])
    if err_response:
        return None, None, err_response
    api_key, nonce, param = params
    res, reason, api_key = check_auth(db.session, api_key, nonce, sig, request.data)
    if not res:
        return None, None, bad_request(reason)
    return param, api_key, None

def auth_request_get_params(db: SQLAlchemy, param_names: list[str]) -> tuple[list[str], Optional[ApiKey], Optional[Response]]:
    sig = request_get_signature()
    content = request.get_json(force=True)
    if content is None:
        return None, None, bad_request(INVALID_JSON)
    params, err_response = get_json_params(content, ["api_key", "nonce"] + param_names)
    if err_response:
        return None, None, err_response
    api_key, nonce, *_ = params
    res, reason, api_key = check_auth(db.session, api_key, nonce, sig, request.data)
    if not res:
        return None, None, bad_request(reason)
    return params[2:], api_key, None
