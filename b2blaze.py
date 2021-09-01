
import logging
import base64
import hashlib
from io import BytesIO

import requests

from app_core import app

logger = logging.getLogger(__name__)

B2_ACCOUNT_ID = app.config['B2_ACCOUNT_ID']
B2_APPLICATION_KEY = app.config['B2_APPLICATION_KEY']

def backblaze_auth_headers():
    # get auth token
    creds = base64.b64encode((B2_ACCOUNT_ID + ':' + B2_APPLICATION_KEY).encode('ascii')).decode('ascii')
    headers = {'Authorization': 'Basic ' + creds}
    return headers

def backblaze_authorize_account():
    headers = backblaze_auth_headers()
    r = requests.get('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', headers=headers)
    r.raise_for_status()
    data = r.json()
    api_url = data['apiUrl']
    download_url = data['downloadUrl']
    auth_token = data['authorizationToken']
    return api_url, download_url, auth_token

def backblaze_get_bucket_id(api_url, auth_token, bucket):
    # if we have an application key get the account id that represents the mastker application key
    account_id = B2_ACCOUNT_ID
    if len(B2_ACCOUNT_ID) > 12:
        account_id = B2_ACCOUNT_ID[3:][:12]
    headers = {'Authorization': auth_token}
    body = {'accountId': account_id, 'bucketName': bucket}
    r = requests.post(api_url + '/b2api/v2/b2_list_buckets', headers=headers, json=body)
    r.raise_for_status()
    data = r.json()
    bucket_id = data['buckets'][0]['bucketId']
    return bucket_id

def backblaze_get_upload_url(api_url, auth_token, bucket_id):
    headers = {'Authorization': auth_token}
    body = {'bucketId': bucket_id}
    r = requests.post(api_url + '/b2api/v2/b2_get_upload_url', headers=headers, json=body)
    r.raise_for_status()
    data = r.json()
    upload_url = data['uploadUrl']
    upload_auth_token = data['authorizationToken']
    return upload_url, upload_auth_token

def backblaze_upload_file(upload_url, upload_auth_token, filename, bytesio, content_type):
    # calc file size and sha1
    file_content = bytesio.getbuffer()
    file_size = str(len(file_content))
    file_sha1 = hashlib.sha1(file_content).hexdigest()
    # upload pdf
    headers = {'Authorization': upload_auth_token, 'X-Bz-File-Name': '%s' % filename, 'Content-Type': content_type, 'Content-Length': file_size, 'X-Bz-Content-Sha1': file_sha1}
    r = requests.post(upload_url, headers=headers, data=file_content)
    r.raise_for_status()

def backblaze_download_file(download_url, auth_token, bucket, filename):
    headers = {'Authorization': auth_token}
    file_url = '{0}/file/{1}/{2}'.format(download_url, bucket, filename)
    r = requests.get(file_url, headers=headers)
    r.raise_for_status()
    return BytesIO(r.content)

def backup_file(bucket, filename, bytesio, content_type):
    try:
        api_url, _, auth_token = backblaze_authorize_account()
        bucket_id = backblaze_get_bucket_id(api_url, auth_token, bucket)
        upload_url, upload_auth_token = backblaze_get_upload_url(api_url, auth_token, bucket_id)
        backblaze_upload_file(upload_url, upload_auth_token, filename, bytesio, content_type)
        return True
    except Exception as ex: # pylint: disable=broad-except
        logger.error('failed to backup file %s', filename)
        logger.error(ex)
    return False

def restore_file(bucket, filename):
    try:
        _, download_url, auth_token = backblaze_authorize_account()
        bytesio = backblaze_download_file(download_url, auth_token, bucket, filename)
        return bytesio
    except Exception as ex: # pylint: disable=broad-except
        logger.error('failed to download pdf')
        logger.error(ex)
    return None
