from app_core import app
import exch
import exch_mock
import exch_indep

#TODO - use a dependency injector like https://python-dependency-injector.ets-labs.org

mock = app.config['EXCHANGE_ACCOUNT_MOCK']
api_key = api_secret = ''
if not mock:
    api_key = app.config['EXCH_API_KEY']
    api_secret = app.config['EXCH_API_SECRET']
testnet = app.config['TESTNET']

if testnet and not mock:
    raise Exception('independent reserve has no testnet')

def exch_factory() -> exch.ExchInterface:
    if mock:
        return exch_mock.ExchMock()
    return exch_indep.ExchIndep(api_key, api_secret)
