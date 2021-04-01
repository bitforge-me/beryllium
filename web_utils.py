
import logging
from flask import jsonify

logger = logging.getLogger(__name__)

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
