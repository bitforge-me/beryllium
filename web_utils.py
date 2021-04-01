
import logging
from flask import jsonify
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

def bad_request(message, code=400):
    logger.warning(message)
    response = jsonify({'message': message})
    response.status_code = code
    return response

def get(url):
    with requests.Session() as s:
        retries = Retry(
            total=10,
            backoff_factor=0.2,
            status_forcelist=[500, 502, 503, 504])
        s.mount('http://', HTTPAdapter(max_retries=retries))
        s.mount('https://', HTTPAdapter(max_retries=retries))
        response = s.get(url)
        return response

def get_json_params(json_content, param_names):
    param_values = []
    param_name = ''
    try:
        for param in param_names:
            param_name = param
            param_values.append(json_content[param])
    except Exception as e:
        logger.error(f"'{param_name}' not found")
        logger.error(e)
        return param_values, bad_request(f"'{param_name}' not found")
    return param_values, None
