# pylint: disable=too-few-public-methods

import datetime

from flask import redirect, url_for, request, has_app_context, g, abort
import flask_admin
from flask_admin import helpers as admin_helpers
from flask_admin.babel import lazy_gettext
from flask_admin.contrib import sqla
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from flask_admin.model import filters, typefmt
from flask_security import current_user
from markupsafe import Markup

from app_core import app, db
from models import Role, User, ApiKey, Topic, PushNotificationLocation, Referral, BrokerOrder, ExchangeOrder, CryptoWithdrawal, CryptoDeposit, CryptoAddress, KycRequest, AplyId, FiatDbTransaction, FiatDeposit, FiatWithdrawal, WindcavePaymentRequest, PayoutRequest
from security import security

# helper functions/classes

class ReloadingIterator:
    def __init__(self, iterator_factory):
        self.iterator_factory = iterator_factory

    def __iter__(self):
        return self.iterator_factory()

# flask admin formatters

def _date_format(view, value):
    return value.strftime('%Y.%m.%d %H:%M')

MY_DEFAULT_FORMATTERS = dict(typefmt.BASE_FORMATTERS)
MY_DEFAULT_FORMATTERS.update({
    datetime.date: _date_format,
})

def _format_location(view, context, model, name):
    lat = model.latitude
    lon = model.longitude
    html = f'''
    <a href="http://www.google.com/maps/place/{lat},{lon}">{lat}, {lon}</a>
    '''
    return Markup(html)

# flask admin filters

class DateBetweenFilter(BaseSQLAFilter, filters.BaseDateBetweenFilter):
    def __init__(self, column, name, options=None, data_type=None):
        # pylint: disable=super-with-arguments
        super(DateBetweenFilter, self).__init__(column,
                                                name,
                                                options,
                                                data_type='daterangepicker')

    def apply(self, query, value, alias=None):
        start, end = value
        return query.filter(self.get_column(alias).between(start, end))

class FilterEqual(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(self.get_column(alias) == value)

    def operation(self):
        return lazy_gettext('equals')

class FilterNotEqual(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(self.get_column(alias) != value)

    def operation(self):
        return lazy_gettext('not equal')

class FilterGreater(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(self.get_column(alias) > value)

    def operation(self):
        return lazy_gettext('greater than')

class FilterSmaller(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(self.get_column(alias) < value)

    def operation(self):
        return lazy_gettext('smaller than')

class DateTimeGreaterFilter(FilterGreater, filters.BaseDateTimeFilter):
    pass

class DateSmallerFilter(FilterSmaller, filters.BaseDateFilter):
    pass

def get_users():
    # prevent database access when app is not yet ready
    if has_app_context():
        if not hasattr(g, 'users'):
            query = User.query.order_by(User.email)
            # pylint: disable=assigning-non-slot
            g.users = [(user.id, user.email) for user in query]
        for user_id, user_email in g.users:
            yield user_id, user_email

class FilterByUserEmail(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(User.id == value)

    def operation(self):
        return 'equals'

    def get_options(self, view):
        # return a generator that is reloaded each time it is used
        return ReloadingIterator(get_users)

def get_broker_order_assets():
    # prevent database access when app is not yet ready
    if has_app_context():
        if not hasattr(g, 'assets'):
            query = BrokerOrder.query.with_entities(BrokerOrder.base_asset).distinct()
            # pylint: disable=assigning-non-slot
            g.assets = [(broker_order.base_asset, broker_order.base_asset) for broker_order in query]
        for base_asset_a, base_asset_b in g.assets:
            yield base_asset_a, base_asset_b

class FilterByBrokerOrderAsset(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(BrokerOrder.base_asset == value)

    def operation(self):
        return 'equals'

    def get_options(self, view):
        # return a generator that is reloaded each time it is used
        return ReloadingIterator(get_broker_order_assets)

# model view classes

class BaseModelView(sqla.ModelView):
    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                return abort(403)
            # login
            return redirect(url_for('security.login', next=request.url))
        return None

class RestrictedModelView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False
    column_exclude_list = ['password', 'secret']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                (current_user.has_role(Role.ROLE_ADMIN) or
                current_user.has_role(Role.ROLE_FINANCE)))

class BaseOnlyUserOwnedModelView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False
    column_exclude_list = ['password', 'secret']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated)

    def get_query(self):
        return self.session.query(self.model).filter(self.model.user==current_user)

    def get_count_query(self):
        return self.session.query(db.func.count('*')).filter(self.model.user==current_user) # pylint: disable=no-member

class UserModelView(BaseModelView):
    can_export = True
    can_create = False
    can_delete = False
    can_edit = False
    column_list = ['token', 'email', 'roles', 'active', 'confirmed_at']
    column_filters = [FilterByUserEmail(User.email, 'Search email'), \
        DateBetweenFilter(User.confirmed_at, 'Search Date')]

    def is_accessible(self):
        if not (current_user.is_active and current_user.is_authenticated):
            return False
        if current_user.has_role(Role.ROLE_FINANCE) and not current_user.has_role(Role.ROLE_ADMIN):
            return True
        return False

class AdminUserModelView(UserModelView):
    column_editable_list = ['roles', 'active']

    def is_accessible(self):
        if not (current_user.is_active and current_user.is_authenticated):
            return False
        if current_user.has_role(Role.ROLE_ADMIN):
            return True
        return False

class ApiKeyModelView(BaseOnlyUserOwnedModelView):
    can_create = False
    can_delete = True
    can_edit = False
    column_list = ('token', 'device_name', 'expiry', 'permissions')
    column_labels = dict(token='API Key')

class PushNotificationLocationModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False

    column_list = ['date', 'location', 'fcm_registration_token']
    column_formatters = {'location': _format_location}

class BrokerOrderModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False

    column_filters = [ DateBetweenFilter(BrokerOrder.date, 'Search Date'), FilterByBrokerOrderAsset(BrokerOrder.base_asset, 'Search asset'), ]

#
# Create admin
#

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
admin.add_view(BrokerOrderModelView(BrokerOrder, db.session, category='Admin'))
admin.add_view(RestrictedModelView(ExchangeOrder, db.session, category='Admin'))
admin.add_view(RestrictedModelView(CryptoWithdrawal, db.session, category='Admin'))
admin.add_view(RestrictedModelView(CryptoDeposit, db.session, category='Admin'))
admin.add_view(RestrictedModelView(CryptoAddress, db.session, category='Admin'))
admin.add_view(RestrictedModelView(FiatWithdrawal, db.session, category='Admin'))
admin.add_view(RestrictedModelView(FiatDeposit, db.session, category='Admin'))
admin.add_view(RestrictedModelView(WindcavePaymentRequest, db.session, category='Admin'))
admin.add_view(RestrictedModelView(PayoutRequest, db.session, category='Admin'))
admin.add_view(RestrictedModelView(FiatDbTransaction, db.session, category='Admin'))
admin.add_view(RestrictedModelView(KycRequest, db.session, category='Admin'))
admin.add_view(RestrictedModelView(AplyId, db.session, category='Admin'))
admin.add_view(ApiKeyModelView(ApiKey, db.session, category='User'))
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
