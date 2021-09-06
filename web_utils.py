import hmac
import hashlib
import base64
import logging

from flask import jsonify, request

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
NOT_IMPLEMENTED  = 'net yet implemented'
NOT_AVAILABLE = 'not available'
INVALID_AMOUNT = 'invalid amount'
INVALID_MARKET = 'invalid market'
INVALID_SIDE = 'invalid side'
INSUFFICIENT_LIQUIDITY = 'insufficient liquidity'
AMOUNT_TOO_LOW = 'amount too low'
INVALID_RECIPIENT = 'invalid recipient'
EXPIRED = 'expired'
INVALID_STATUS = 'invalid status'
FAILED_PAYMENT_CREATE = 'failed payment create'
KYC_REQUEST_EXISTS = 'kyc request exists'
KYC_NOT_VALIDATED = 'kyc not validated'
INVALID_PARAMETER = 'invalid parameter'

def bad_request(message, code=400):
    logger.warning(message)
    response = jsonify({'message': message})
    response.status_code = code
    return response

def get_json_params(json_content, param_names):
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

def get_json_params_optional(json_content, param_names):
    param_values = []
    for param in param_names:
        try:
            param_values.append(json_content[param])
        except Exception: # pylint: disable=broad-except
            param_values.append(None)
    return param_values

def to_bytes(data):
    if not isinstance(data, (bytes, bytearray)):
        return data.encode("utf-8")
    return data

def create_hmac_sig(api_secret, message):
    _hmac = hmac.new(to_bytes(api_secret), msg=to_bytes(message), digestmod=hashlib.sha256)
    signature = _hmac.digest()
    signature = base64.b64encode(signature).decode("utf-8")
    return signature

def request_get_signature():
    return request.headers.get('X-Signature')

def check_hmac_auth(api_key, nonce, sig, body):
    if int(nonce) <= int(api_key.nonce):
        return False, OLD_NONCE
    our_sig = create_hmac_sig(api_key.secret, body)
    if sig == our_sig:
        api_key.nonce = nonce
        return True, ""
    return False, AUTH_FAILED

def check_auth(session, api_key_token, nonce, sig, body):
    # pylint: disable=import-outside-toplevel
    from models import ApiKey
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
def auth_request(db):
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
        return None, None, bad_request(reason)
    return api_key, None

# pylint: disable=unbalanced-tuple-unpacking
# pylint: disable=invalid-name
def auth_request_get_single_param(db, param_name):
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

def auth_request_get_params(db, param_names):
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
