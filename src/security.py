import logging
import io
import base64

from flask import redirect, url_for, request, flash
from flask_security.core import Security
from flask_security.datastore import SQLAlchemyUserDatastore
from flask_login.utils import current_user
import flask_security.forms
import flask_security.utils
from flask_security.utils import config_value as cv
from flask_security.proxies import _security
from wtforms import StringField, SubmitField
import qrcode
import qrcode.image.pil

from app_core import app, db, limiter
from models import User, Role
import tripwire

logger = logging.getLogger(__name__)

#
# Helper functions
#

def tf_method() -> str:
    methods = cv("TWO_FACTOR_ENABLED_METHODS")
    assert methods and len(methods) == 1
    return methods[0]

def tf_enabled_check(user: User) -> bool:
    return user.tf_primary_method is not None

def tf_secret_init(user: User):
    totp_factory = _security._totp_factory
    user.tf_totp_secret = totp_factory.generate_totp_secret()
    setup_values = totp_factory.fetch_setup_values(user.tf_totp_secret, user)

    # make backup png image
    image = qrcode.make(
        totp_factory.get_totp_uri(user.calc_username(), user.tf_totp_secret),
        image_factory=qrcode.image.pil.PilImage,
    )
    with io.BytesIO() as virtual_file:
        image.save(virtual_file)
        image_as_str = base64.b64encode(virtual_file.getvalue()).decode("ascii")
    setup_values['image_png_base64'] = image_as_str
    return setup_values

def tf_method_set(user: User):
    user.tf_primary_method = tf_method()

def tf_method_unset(user: User):
    user.tf_primary_method = None

def tf_code_send(user: User) -> bool:
    if tf_method() == "email":
        msg = user.tf_send_security_token(method="email", totp_secret=user.tf_totp_secret, phone_number=None)
        if msg:
            logger.error('failed to send two factor code to user %s (%s)', user.email, msg)
        return not msg
    return True

def tf_code_validate(user: User, code: str) -> bool:
    # codes sent by sms or mail will be valid for another window cycle
    if user.tf_primary_method in ('google_authenticator', 'authenticator'):
        window = cv("TWO_FACTOR_AUTHENTICATOR_VALIDITY")
    elif user.tf_primary_method in ('email', 'mail'):
        window = cv("TWO_FACTOR_MAIL_VALIDITY")
    elif user.tf_primary_method == 'sms':
        window = cv("TWO_FACTOR_SMS_VALIDITY")
    else:
        logger.error('no valid two factor method for user %s', user.email)
        return False

    # verify entered token with user's totp secret
    if not window or not user.tf_totp_secret or not _security._totp_factory.verify_totp(
        token=code,
        totp_secret=user.tf_totp_secret,
        user=user,
        window=window,
    ):
        return False

    return True

#
# Custom security forms
#

@app.before_request
def check_verify():
    # we need to manually send the two factor security token because we cant change the
    # 'verify' view in flask_security.views
    if current_user.is_active and current_user.is_authenticated and \
       current_user.tf_primary_method and \
       request.path == url_for('security.verify') and request.method == 'GET':
        msg = current_user.tf_send_security_token(
            method=current_user.tf_primary_method,
            totp_secret=current_user.tf_totp_secret,
            phone_number=getattr(current_user, "tf_phone_number", None),
        )
        if msg:
            # send code didn't work
            flash(msg, "danger")

    # trigger all login attempts
    if request.path == url_for('security.login') and request.method == 'POST':
        tripwire.login_attempt()


class SecureVerifyForm(flask_security.forms.VerifyForm):

    # we add the 2fa code checking to the verify form
    code = StringField(flask_security.forms.get_form_field_label("code"))
    submit = SubmitField("Verify")

    def validate(self, extra_validators=None):
        if not super().validate():
            return False
        if not self.user:
            return False
        if self.user.tf_primary_method:  # validate tf code if enabled
            return tf_code_validate(self.user, self.code.data)
        return True

#
# Setup Flask-Security
#

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, verify_form=SecureVerifyForm)
# set rate limits for security endpoints
limiter.limit('100/minute')(app.blueprints['security'])
def _limit_view_function(view_name, limit_func):
    app.view_functions[view_name] = limit_func(app.view_functions[view_name])
_limit_view_function('security.login', limiter.limit('10/hour'))
if app.config['SECURITY_REGISTERABLE']:
    _limit_view_function('security.register', limiter.limit('10/hour'))
_limit_view_function('security.forgot_password', limiter.limit('10/hour'))
_limit_view_function('security.reset_password', limiter.limit('10/hour'))

# we need to override the default handler which does not handle SECURITY_URL_PREFIX
# see https://github.com/Flask-Middleware/flask-security/issues/526
@security.reauthn_handler
def my_reauthn(within, grace, headers=None):
    m, c = flask_security.utils.get_message("REAUTHENTICATION_REQUIRED")
    flash(m, c)
    redirect_url = url_for('security.verify', next=request.url)
    return redirect(redirect_url)
