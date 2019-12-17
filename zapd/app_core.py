import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail_sendgrid import MailSendGrid

import config
cfg = config.read_cfg()

# Create Flask application
app = Flask(__name__)
app.config.from_pyfile("flask_config.py")
app.config.from_pyfile("flask_config_secret.py")
if os.getenv("DEBUG"):
    app.config["DEBUG"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = cfg.db_filename
if os.getenv("SESSION_KEY"):
    app.config["SECRET_KEY"] = os.getenv("SESSION_KEY")
if os.getenv("PASSWORD_SALT"):
    app.config["SECURITY_PASSWORD_SALT"] = os.getenv("PASSWORD_SALT")
if os.getenv("SENDGRID_API_KEY"):
    app.config["MAIL_SENDGRID_API_KEY"] = os.getenv("SENDGRID_API_KEY")
db = SQLAlchemy(app)
mail = MailSendGrid(app)
