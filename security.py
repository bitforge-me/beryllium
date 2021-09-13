from flask import redirect, url_for, request, flash
from flask_security import Security, SQLAlchemyUserDatastore, current_user
import flask_security.forms
import flask_security.utils
from flask_security.utils import config_value as cv
from flask_security.proxies import _security
from wtforms import StringField, SubmitField

from app_core import app, db
from models import User, Role

#
# Helper functions
#

def validate_totp(user, code):
    # codes sent by sms or mail will be valid for another window cycle
    if (
        user.tf_primary_method == "google_authenticator"
        or user.tf_primary_method == "authenticator"
    ):
        window = cv("TWO_FACTOR_AUTHENTICATOR_VALIDITY")
    elif user.tf_primary_method == "email" or user.tf_primary_method == "mail":
        window = cv("TWO_FACTOR_MAIL_VALIDITY")
    elif user.tf_primary_method == "sms":
        window = cv("TWO_FACTOR_SMS_VALIDITY")
    else:
        return False

    # verify entered token with user's totp secret
    # pylint: disable=protected-access
    if not _security._totp_factory.verify_totp(
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
        request.path == url_for('security.verify') and request.method == 'GET':
        msg = current_user.tf_send_security_token(
            method=current_user.tf_primary_method,
            totp_secret=current_user.tf_totp_secret,
            phone_number=getattr(current_user, "tf_phone_number", None),
        )
        if msg:
            # send code didn't work
            flash(msg, "error")

class SecureVerifyForm(flask_security.forms.VerifyForm):

    code = StringField(flask_security.forms.get_form_field_label("code"))
    submit = SubmitField("Verify")

    def validate(self):
        if not super().validate():
            return False

        return validate_totp(self.user, self.code.data)

class SecureTwoFactorSetupForm(flask_security.forms.TwoFactorSetupForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if current_user.tf_primary_method:
            # only have the 'disable' option
            self.setup.choices = self.setup.choices[-1]
        else:
            # remove the 'disable' option
            self.setup.choices = self.setup.choices[:-1]

    def validate(self):
        # only allow a user to setup a new method if no current method enabled
        data = self.data # pylint: disable=no-member
        if "setup" in data:
            choice = data["setup"]
            if current_user.tf_primary_method and choice != "disable":
                return False
            if not current_user.tf_primary_method and choice == "disable":
                return False
        return super().validate()

class SecureTwoFactorRescueForm(flask_security.forms.TwoFactorRescueForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # remove the lost device option
        self.help_setup.choices.pop(0)

    def validate(self):
        # do not allow the lost device option
        data = self.data # pylint: disable=no-member
        if "help_setup" in data:
            choice = data["help_setup"]
            if choice == "lost_device":
                return False
        return super().validate()

#
# Setup Flask-Security
#

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, verify_form=SecureVerifyForm, two_factor_setup_form=SecureTwoFactorSetupForm, two_factor_rescue_form=SecureTwoFactorRescueForm)

# we need to override the default handler which does not handle SECURITY_URL_PREFIX
# see https://github.com/Flask-Middleware/flask-security/issues/526
@security.reauthn_handler
def my_reauthn(within, grace, headers=None):
    m, c = flask_security.utils.get_message("REAUTHENTICATION_REQUIRED")
    flash(m, c)
    redirect_url = url_for('security.verify', next=request.url)
    return redirect(redirect_url)
