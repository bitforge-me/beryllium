import json as json_parse

from geventhttpclient import HTTPClient
from geventhttpclient.url import URL
from geventhttpclient.response import HTTPSocketPoolResponse

"""
Mimic the way we used the 'requests library but instead use 'geventhttpclient'
in order to be cooperative with gevent
"""

class HttpReqResponse:
    body: bytearray | None = None

    def __init__(self, url: str, response: HTTPSocketPoolResponse):
        self.url = url
        self.response = response

    def raise_for_status(self):
        status_code = self.response.status_code
        if status_code < 200 or status_code >= 300:
            raise Exception('status_code < 200 or status_code >= 300')

    @property
    def status_code(self):
        return self.response.status_code

    @property
    def content(self) -> bytearray:
        if self.body:
            return self.body
        self.body = self.response.read()
        return self.body

    @property
    def text(self):
        return self.content.decode()

    def json(self):
        return json_parse.loads(self.response.read())

def get(url: str, headers: dict = {}, params: dict = {}):
    url_ = URL(url)
    if params:
        for key in params:
            url_[key] = params[key]
    http = HTTPClient(url_.host)
    response = http.get(url_.request_uri, headers=headers)
    return HttpReqResponse(url, response)

def post(url: str, headers: dict = {}, data: str = '', json: dict | None = None):
    url_ = URL(url)
    http = HTTPClient(url_.host)
    if json:
        data = json_parse.dumps(json)
    response = http.post(url_.request_uri, body=data, headers=headers)
    return HttpReqResponse(url, response)

def put(url: str, headers: dict = {}, data: str = '', json: dict | None = None):
    url_ = URL(url)
    http = HTTPClient(url_.host)
    if json:
        data = json_parse.dumps(json)
    response = http.put(url_.request_uri, body=data, headers=headers)
    return HttpReqResponse(url, response)
