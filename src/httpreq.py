import requests
from requests import Response

def get(url: str, headers: dict = {}, params: dict = {}):
    return requests.get(url, headers=headers, params=params)

def post(url: str, headers: dict = {}, data: str = '', json: dict | None = None):
    return requests.post(url, headers=headers, data=data, json=json)

def put(url: str, headers: dict = {}, data: str = '', json: dict | None = None):
    return requests.put(url, headers=headers, data=data, json=json)

if __name__ == '__main__':
    urls = [
        'https://www.youtube.com',
        'https://www.facebook.com',
        'https://www.baidu.com',
        'https://www.yahoo.com',
        'https://www.amazon.com',
        'https://www.wikipedia.org',
        'https://www.qq.com',
        'https://www.google.co.in',
        'https://www.twitter.com',
        'https://www.live.com',
        'https://www.taobao.com',
        'https://www.bing.com',
        'https://www.instagram.com',
        'https://www.weibo.com',
        'https://www.sina.com.cn',
        'https://www.linkedin.com',
        'https://www.yahoo.co.jp',
        'https://www.msn.com',
        'https://www.vk.com',
        'https://www.google.de',
        'https://www.yandex.ru',
        'https://www.hao123.com',
        'https://www.google.co.uk',
        'https://www.reddit.com',
        'https://www.ebay.com',
        'https://www.google.fr',
        'https://www.t.co',
        'https://www.tmall.com',
        'https://www.google.com.br',
        'https://www.360.cn',
        'https://www.sohu.com',
        'https://www.amazon.co.jp',
        'https://www.pinterest.com',
        'https://www.netflix.com',
        'https://www.google.it',
        'https://www.google.ru',
        'https://www.microsoft.com',
        'https://www.google.es',
        'https://www.wordpress.com',
        'https://www.gmw.cn',
        'https://www.tumblr.com',
        'https://www.paypal.com',
        'https://www.blogspot.com',
        'https://www.imgur.com',
        'https://www.stackoverflow.com',
        'https://www.aliexpress.com',
        'https://www.naver.com',
        'https://www.ok.ru',
        'https://www.apple.com',
        'https://www.github.com',
        'https://www.chinadaily.com.cn',
        'https://www.imdb.com',
        'https://www.google.co.kr',
        'https://www.fc2.com',
        'https://www.jd.com',
        'https://www.blogger.com',
        'https://www.163.com',
        'https://www.google.ca',
        'https://www.whatsapp.com',
        'https://www.amazon.in',
        'https://www.office.com',
        'https://www.tianya.cn',
        'https://www.google.co.id',
        'https://www.youku.com',
        'https://www.rakuten.co.jp',
        'https://www.craigslist.org',
        'https://www.amazon.de',
        'https://www.nicovideo.jp',
        'https://www.google.pl',
        'https://www.soso.com',
        'https://www.bilibili.com',
        'https://www.dropbox.com',
        'https://www.xinhuanet.com',
        'https://www.outbrain.com',
        'https://www.pixnet.net',
        'https://www.alibaba.com',
        'https://www.alipay.com',
        'https://www.microsoftonline.com',
        'https://www.booking.com',
        'https://www.googleusercontent.com',
        'https://www.google.com.au',
        'https://www.popads.net',
        'https://www.cntv.cn',
        'https://www.zhihu.com',
        'https://www.amazon.co.uk',
        'https://www.diply.com',
        'https://www.coccoc.com',
        'https://www.cnn.com',
        'https://www.bbc.co.uk',
        'https://www.twitch.tv',
        'https://www.wikia.com',
        'https://www.google.co.th',
        'https://www.go.com',
        'https://www.google.com.ph',
        'https://www.doubleclick.net',
        'https://www.onet.pl',
        'https://www.googleadservices.com',
        'https://www.accuweather.com',
        'https://www.googleweblight.com',
        'https://www.answers.yahoo.com'
    ]

    def test_url(url, stop_on_execept=True):
        try:
            print(url)
            r = get(url)
            print(r.status_code)
            print(r.text[:250])
            print()
        except Exception as ex:
            print(ex)
            if stop_on_execept:
                return

    test_url('https://www.howsmyssl.com/a/check')
    for url in urls:
        test_url(url)
