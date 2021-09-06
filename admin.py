from flask import url_for
import flask_admin
from flask_admin import helpers as admin_helpers

from app_core import app, db
from models import security, RestrictedModelView, BaseOnlyUserOwnedModelView, UserModelView, AdminUserModelView, PayDbApiKeyModelView, PushNotificationLocationModelView, \
    Role, User, ApiKey, Topic, PushNotificationLocation, Referral, BrokerOrder, ExchangeOrder, ExchangeWithdrawal, KycRequest, AplyId

# Create admin
admin = flask_admin.Admin(
    app,
    'Beryllium Admin',
    base_template='my_master.html',
    template_mode='bootstrap3',
)

# Add model views
admin.add_view(UserModelView(User, db.session, category='Admin'))
admin.add_view(AdminUserModelView(User, db.session, category='Admin', endpoint='AdminUser'))
admin.add_view(RestrictedModelView(Role, db.session, category='Admin'))
admin.add_view(RestrictedModelView(Topic, db.session, category='Admin'))
admin.add_view(PushNotificationLocationModelView(PushNotificationLocation, db.session, category='Admin'))
admin.add_view(RestrictedModelView(BrokerOrder, db.session, category='Admin'))
admin.add_view(RestrictedModelView(ExchangeOrder, db.session, category='Admin'))
admin.add_view(RestrictedModelView(ExchangeWithdrawal, db.session, category='Admin'))
admin.add_view(RestrictedModelView(KycRequest, db.session, category='Admin'))
admin.add_view(RestrictedModelView(AplyId, db.session, category='Admin'))
admin.add_view(PayDbApiKeyModelView(ApiKey, db.session, category='User'))
if app.config["USE_REFERRALS"]:
    admin.add_view(RestrictedModelView(Referral, db.session, category='Admin', name='Referrals'))
    admin.add_view(BaseOnlyUserOwnedModelView(Referral, db.session, category='User', name='Referrals', endpoint='UserReferrals'))

# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )
