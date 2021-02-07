import os
import json

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail_sendgrid import MailSendGrid

missing_vital_setting = False

# Create Flask application
app = Flask(__name__)

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

def set_vital_setting(env_name, setting_name=None, acceptable_values=None):
    global missing_vital_setting
    if not setting_name:
        setting_name = env_name
    if os.getenv(env_name):
        value = app.config[setting_name] = os.getenv(env_name)
        app.config[env_name] = os.getenv(env_name)
        if acceptable_values and value not in acceptable_values:
            print(env_name + " not in range of acceptable values: " + str(acceptable_values))
            missing_vital_setting = True
    else:
        print("no " + env_name)
        missing_vital_setting = True

set_vital_setting("SERVER_MODE", acceptable_values=["waves", "paydb"])
if app.config["SERVER_MODE"] == "waves":
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
        raise Exception('TX_SIGNERS is not valid json')
else: # paydb
    set_vital_setting("ASSET_NAME")

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
