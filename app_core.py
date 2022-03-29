import os
import decimal

from flask import Flask
import flask.json
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_mail_sendgrid import MailSendGrid
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

SERVER_VERSION = 7
CLIENT_VERSION_DEPLOYED = 6

MISSING_VITAL_SETTING = False

class MyJSONEncoder(flask.json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            # Convert decimal instances to strings.
            return str(o)
        return super().default(o)

# Create Flask application
app = Flask(__name__)
app.json_encoder = MyJSONEncoder
app.wsgi_app = ProxyFix(app.wsgi_app)
all_origins = {"origins": "*"}
cors = CORS(app, resources={r"/apiv1/*": all_origins})

if os.getenv("DEBUG"):
    app.config["DEBUG"] = True

app.config.from_pyfile("flask_config.py")

if os.getenv("TESTNET"):
    app.config["TESTNET"] = True
else:
    app.config["TESTNET"] = False
if os.getenv("DATABASE_URL"):
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
if os.getenv("LOGO_URL_SRC"):
    app.config["LOGO_URL_SRC"] = os.getenv("LOGO_URL_SRC")
else:
    app.config["LOGO_URL_SRC"] = "/static/assets/img/logo.png"

if os.getenv("LOGO_EMAIL_SRC"):
    app.config["LOGO_EMAIL_SRC"] = os.getenv("LOGO_EMAIL_SRC")
else:
    app.config["LOGO_EMAIL_SRC"] = "http://" + os.getenv("SERVER_NAME") + "/static/assets/img/logo.png"

if os.getenv("APPLE_APP_STORE_URL"):
    app.config["APPLE_APP_STORE_URL"] = os.getenv("APPLE_APP_STORE_URL")
else:
    app.config["APPLE_APP_STORE_URL"] = "https://apps.apple.com/nz/app/zap/XXX"

if os.getenv("GOOGLE_PLAY_STORE_URL"):
    app.config["GOOGLE_PLAY_STORE_URL"] = os.getenv("GOOGLE_PLAY_STORE_URL")
else:
    app.config["GOOGLE_PLAY_STORE_URL"] = "https://play.google.com/store/apps/details?id=XXX"

if os.getenv("USE_REFERRALS"):
    app.config["USE_REFERRALS"] = True
else:
    app.config["USE_REFERRALS"] = False
#if os.getenv("REFERRAL_REWARD_TYPE_SENDER"):
#    app.config["REFERRAL_REWARD_TYPE_SENDER"] = os.getenv("REFERRAL_REWARD_TYPE_SENDER")
#else:
app.config["REFERRAL_REWARD_TYPE_SENDER"] = 'fixed'
if os.getenv("REFERRAL_REWARD_SENDER"):
    app.config["REFERRAL_REWARD_SENDER"] = int(os.getenv("REFERRAL_REWARD_SENDER"))
else:
    app.config["REFERRAL_REWARD_SENDER"] = 1000
if os.getenv("REFERRAL_REWARD_TYPE_RECIPIENT"):
    app.config["REFERRAL_REWARD_TYPE_RECIPIENT"] = os.getenv("REFERRAL_REWARD_TYPE_RECIPIENT")
else:
    app.config["REFERRAL_REWARD_TYPE_RECIPIENT"] = 'fixed'
if os.getenv("REFERRAL_REWARD_RECIPIENT"):
    app.config["REFERRAL_REWARD_RECIPIENT"] = int(os.getenv("REFERRAL_REWARD_RECIPIENT"))
else:
    app.config["REFERRAL_REWARD_RECIPIENT"] = 1000
if os.getenv("REFERRAL_RECIPIENT_MIN_SPEND"):
    app.config["REFERRAL_RECIPIENT_MIN_SPEND"] = int(os.getenv("REFERRAL_RECIPIENT_MIN_SPEND"))
else:
    app.config["REFERRAL_RECIPIENT_MIN_SPEND"] = 5000
if os.getenv("REFERRAL_ECOMMERCE_URL"):
    app.config["REFERRAL_ECOMMERCE_URL"] = os.getenv("REFERRAL_ECOMMERCE_URL")
else:
    app.config["REFERRAL_ECOMMERCE_URL"] = None
if os.getenv("REFERRAL_STORE_NAME"):
    app.config["REFERRAL_STORE_NAME"] = os.getenv("REFERRAL_STORE_NAME")
else:
    app.config["REFERRAL_STORE_NAME"] = "Change My Name Inc"
if os.getenv("REFERRAL_SPEND_ASSET"):
    app.config["REFERRAL_SPEND_ASSET"] = os.getenv("REFERRAL_SPEND_ASSET")
else:
    app.config["REFERRAL_SPEND_ASSET"] = "NZD"

if os.getenv("BROKER_ORDER_FEE"):
    app.config["BROKER_ORDER_FEE"] = os.getenv("BROKER_ORDER_FEE")
else:
    app.config["BROKER_ORDER_FEE"] = "2.5"

if os.getenv('EXCHANGE_ACCOUNT_MOCK'):
    app.config['EXCHANGE_ACCOUNT_MOCK'] = True
else:
    app.config['EXCHANGE_ACCOUNT_MOCK'] = False

if os.getenv('REGISTRATION_DISABLE'):
    app.config['SECURITY_REGISTERABLE'] = False

if os.getenv("FLASK_ADMIN_SWATCH"):
    app.config["FLASK_ADMIN_SWATCH"] = os.getenv("FLASK_ADMIN_SWATCH")

if os.getenv("FLASK_ADMIN_SWATCH") == "slate":
    app.config["CSS_THEME"] = "css/custom_reporting_dark.css"
    app.config["CSS_THEME_INTENSITY"] = "dark"
else:
    app.config["CSS_THEME_INTENSITY"] = "light"

if os.getenv("MIN_AVAILABLE_NZD_BALANCE"):
    app.config["MIN_AVAILABLE_NZD_BALANCE"] = decimal.Decimal(os.getenv("MIN_AVAILABLE_NZD_BALANCE"))
else:
    app.config["MIN_AVAILABLE_NZD_BALANCE"] = decimal.Decimal(2000)

if os.getenv("BITCOIND_RPC_URL"):
    app.config["BITCOIND_RPC_URL"] = os.getenv("BITCOIND_RPC_URL")
else:
    app.config["BITCOIND_RPC_URL"] = ""

if app.config["TESTNET"]:
    app.config["BITCOIN_EXPLORER"] = "https://blockstream.info/testnet/"
else:
    app.config["BITCOIN_EXPLORER"] = "https://blockstream.info/"

def set_vital_setting(env_name, setting_name=None, acceptable_values=None, custom_handler=None):
    # pylint: disable=global-statement
    global MISSING_VITAL_SETTING
    if not setting_name:
        setting_name = env_name
    if os.getenv(env_name):
        value = app.config[setting_name] = os.getenv(env_name)
        app.config[env_name] = os.getenv(env_name)
        if acceptable_values and value not in acceptable_values:
            print(env_name + " not in range of acceptable values: " + str(acceptable_values))
            MISSING_VITAL_SETTING = True
        if custom_handler:
            custom_handler(env_name, value)
    else:
        print("no " + env_name)
        MISSING_VITAL_SETTING = True

set_vital_setting("ADMIN_EMAIL", "SECURITY_TWO_FACTOR_RESCUE_MAIL")
set_vital_setting("FROM_EMAIL", "SECURITY_EMAIL_SENDER")
set_vital_setting("FROM_NAME")

set_vital_setting("SESSION_KEY", "SECRET_KEY")
def set_totp_secret(name, val):
    app.config["SECURITY_TOTP_SECRETS"] = {'1': val}
set_vital_setting("PASSWORD_SALT", "SECURITY_PASSWORD_SALT", custom_handler=set_totp_secret)
set_vital_setting("SENDGRID_API_KEY", "MAIL_SENDGRID_API_KEY")
set_vital_setting("SERVER_NAME")
set_vital_setting("FIREBASE_CREDENTIALS")
set_vital_setting("DASSET_API_SECRET")
set_vital_setting("DASSET_ACCOUNT_ID")
set_vital_setting("DASSET_TOTP_KEY")
set_vital_setting("PAYOUT_GROUP_EMAIL")
set_vital_setting("APLYID_BASE_URL")
set_vital_setting("APLYID_API_KEY")
set_vital_setting("APLYID_API_SECRET")
set_vital_setting("APLYID_WEBHOOK_BEARER_TOKEN")
set_vital_setting("B2_ACCOUNT_ID")
set_vital_setting("B2_APPLICATION_KEY")
set_vital_setting("KYC_BUCKET")

db = SQLAlchemy(app)
mail = MailSendGrid(app)
socketio = SocketIO(app, cors_allowed_origins='*')
limiter = Limiter(app, key_func=get_remote_address, headers_enabled=True, default_limits=["3000 per minute"])
