import os
import json

import pywaves
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_mail_sendgrid import MailSendGrid
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

SERVER_MODE_WAVES = 'waves'
SERVER_MODE_PAYDB = 'paydb'
MISSING_VITAL_SETTING = False

# Create Flask application
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
all_origins = {"origins": "*"}
cors = CORS(app, resources={r"/paydb/*": all_origins, r"/payment_create": all_origins})

if os.getenv("DEBUG"):
    app.config["DEBUG"] = True

app.config.from_pyfile("flask_config.py")

if os.getenv("TESTNET"):
    app.config["TESTNET"] = True
else:
    app.config["TESTNET"] = False
if os.getenv("DATABASE_URL"):
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
else:
    if app.config["TESTNET"]:
        DATABASE_FILE = 'premio_stage_testnet.db'
    else:
        DATABASE_FILE = 'premio_stage.db'
    app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + DATABASE_FILE
if os.getenv("LOGO_URL_SRC"):
    app.config["LOGO_URL_SRC"] = os.getenv("LOGO_URL_SRC")
else:
    app.config["LOGO_URL_SRC"] = "http://" + os.getenv("SERVER_NAME") + "/static/assets/img/logo.svg"

if os.getenv("LOGO_EMAIL_SRC"):
    app.config["LOGO_EMAIL_SRC"] = os.getenv("LOGO_EMAIL_SRC")
else:
    app.config["LOGO_EMAIL_SRC"] = "http://" + os.getenv("SERVER_NAME") + "/static/assets/img/logo.png"

if os.getenv("APPLE_APP_STORE_URL"):
    app.config["APPLE_APP_STORE_URL"] = os.getenv("APPLE_APP_STORE_URL")
else:
    app.config["APPLE_APP_STORE_URL"] = "https://apps.apple.com/nz/app/zap/id1445794886"

if os.getenv("GOOGLE_PLAY_STORE_URL"):
    app.config["GOOGLE_PLAY_STORE_URL"] = os.getenv("GOOGLE_PLAY_STORE_URL")
else:
    app.config["GOOGLE_PLAY_STORE_URL"] = "https://play.google.com/store/apps/details?id=me.zap.zapapp"

if os.getenv("USE_STASH"):
    app.config["USE_STASH"] = True
else:
    app.config["USE_STASH"] = False

def set_vital_setting(env_name, setting_name=None, acceptable_values=None):
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
    else:
        print("no " + env_name)
        MISSING_VITAL_SETTING = True

set_vital_setting("SERVER_MODE", acceptable_values=[SERVER_MODE_WAVES, SERVER_MODE_PAYDB])
set_vital_setting("DEEP_LINK_SCHEME")
if app.config["SERVER_MODE"] == SERVER_MODE_WAVES:
    set_vital_setting("ASSET_NAME")
    if app.config["TESTNET"]:
        app.config["WAVESEXPLORER"] = 'https://testnet.wavesexplorer.com'
    else:
        app.config["WAVESEXPLORER"] = 'https://wavesexplorer.com'
    set_vital_setting("NODE_BASE_URL")
    set_vital_setting("WALLET_SEED")
    set_vital_setting("WALLET_ADDRESS")
    set_vital_setting("ASSET_ID")
    set_vital_setting("ASSET_MASTER_PUBKEY")
    set_vital_setting("TX_SIGNERS")
    try:
        app.config["TX_SIGNERS"] = json.loads(app.config["TX_SIGNERS"])
    except:
        raise Exception('TX_SIGNERS is not valid json') from None

    # set pywaves to offline mode and testnet
    pywaves.setOffline()
    if app.config["TESTNET"]:
        pywaves.setChain("testnet")

else: # paydb
    set_vital_setting("ASSET_NAME")
    set_vital_setting("OPERATIONS_ACCOUNT")

set_vital_setting("ADMIN_EMAIL")
set_vital_setting("FROM_EMAIL", "SECURITY_EMAIL_SENDER")
set_vital_setting("FROM_NAME")

set_vital_setting("SESSION_KEY", "SECRET_KEY")
set_vital_setting("PASSWORD_SALT", "SECURITY_PASSWORD_SALT")
set_vital_setting("SENDGRID_API_KEY", "MAIL_SENDGRID_API_KEY")
set_vital_setting("SERVER_NAME")
set_vital_setting("FIREBASE_CREDENTIALS")

db = SQLAlchemy(app)
mail = MailSendGrid(app)
socketio = SocketIO(app, cors_allowed_origins='*')
limiter = Limiter(app, key_func=get_remote_address, headers_enabled=True, default_limits=["3000 per minute"])
