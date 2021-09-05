# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-arguments
# pylint: disable=no-self-argument
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-locals
# pylint: disable=too-many-lines

import datetime
import logging

from flask import redirect, url_for, request, has_app_context, g, abort
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, current_user
from flask_admin.babel import lazy_gettext
from flask_admin.contrib import sqla
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from flask_admin.model import filters, typefmt
from marshmallow import Schema, fields
from markupsafe import Markup
from sqlalchemy import or_, and_

from app_core import app, db
from utils import generate_key
import dasset

logger = logging.getLogger(__name__)

### helper functions/classes

class ReloadingIterator:
    def __init__(self, iterator_factory):
        self.iterator_factory = iterator_factory

    def __iter__(self):
        return self.iterator_factory()

### Define premio stage models

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    ROLE_ADMIN = 'admin'
    ROLE_FINANCE = 'finance'
    ROLE_PROPOSER = 'proposer'
    ROLE_REFERRAL_CLAIMER = 'referral_claimer'

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    @classmethod
    def from_name(cls, session, name):
        return session.query(cls).filter(cls.name == name).first()

    def __str__(self):
        return f'{self.name}'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255))
    mobile_number = db.Column(db.String(255))
    address = db.Column(db.String(255))
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
    current_login_ip = db.Column(db.String(100))
    login_count = db.Column(db.Integer)
    active = db.Column(db.Boolean())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    confirmed_at = db.Column(db.DateTime())
    tf_totp_secret = db.Column(db.String(255))
    tf_primary_method = db.Column(db.String(255))
    tf_phone_number = db.Column(db.String(255))
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    photo = db.Column(db.String())
    photo_type = db.Column(db.String(255))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.token = generate_key()

    def kyc_validated(self):
        if self.kyc_requests:
            for req in self.kyc_requests:
                if req.validated():
                    return True
        return False

    def kyc_url(self):
        if self.kyc_requests:
            for req in self.kyc_requests:
                return req.url()
        return None

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    def __str__(self):
        return f'{self.email}'

class UserCreateRequest(db.Model):

    MINUTES_EXPIRY = 30

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    mobile_number = db.Column(db.String(255))
    address = db.Column(db.String(255))
    photo = db.Column(db.String())
    photo_type = db.Column(db.String(255))
    password = db.Column(db.String(255))
    expiry = db.Column(db.DateTime())

    def __init__(self, first_name, last_name, email, mobile_number, address, photo, photo_type, password):
        self.token = generate_key()
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.mobile_number = mobile_number
        self.address = address
        self.photo = photo
        self.photo_type = photo_type
        self.password = password
        self.expiry = datetime.datetime.now() + datetime.timedelta(minutes=self.MINUTES_EXPIRY)

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __str__(self):
        return self.email

class UserUpdateEmailRequest(db.Model):

    MINUTES_EXPIRY = 30

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('update_email_requests', lazy='dynamic'))
    expiry = db.Column(db.DateTime())

    def __init__(self, user, email):
        self.token = generate_key()
        self.user = user
        self.email = email
        self.expiry = datetime.datetime.now() + datetime.timedelta(minutes=self.MINUTES_EXPIRY)

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __str__(self):
        return self.email

permissions_api_keys = db.Table(
    'permissions_api_keys',
    db.Column('api_key_id', db.Integer(), db.ForeignKey('api_key.id')),
    db.Column('permission_id', db.Integer(), db.ForeignKey('permission.id'))
)

class Permission(db.Model):
    PERMISSION_RECIEVE = 'receive'
    PERMISSION_BALANCE = 'balance'
    PERMISSION_HISTORY = 'history'
    PERMISSION_TRANSFER = 'transfer'
    PERMISSION_ISSUE = 'issue'
    PERMS_ALL = [PERMISSION_BALANCE, PERMISSION_HISTORY, PERMISSION_ISSUE, PERMISSION_RECIEVE, PERMISSION_TRANSFER]

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    @classmethod
    def from_name(cls, session, name):
        return session.query(cls).filter(cls.name == name).first()

    def __str__(self):
        return f'{self.name}'

class ApiKey(db.Model):
    MINUTES_EXPIRY = 30

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    secret = db.Column(db.String(255), nullable=False)
    nonce = db.Column(db.BigInteger, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('api_keys', lazy='dynamic'))
    device_name = db.Column(db.String(255))
    expiry = db.Column(db.DateTime())
    permissions = db.relationship('Permission', secondary=permissions_api_keys,
                            backref=db.backref('api_keys', lazy='dynamic'))

    def __init__(self, user, device_name):
        self.user_id = user.id
        self.token = generate_key()
        self.secret = generate_key(20)
        self.nonce = 0
        self.device_name = device_name
        self.expiry = datetime.datetime.now() + datetime.timedelta(minutes=self.MINUTES_EXPIRY)

    def has_permission(self, permission_name):
        perm = Permission.from_name(db.session, permission_name)
        if perm:
            return perm in self.permissions # pylint: disable=unsupported-membership-test
        return False

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

class ApiKeyRequest(db.Model):
    MINUTES_EXPIRY = 30

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    secret = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('api_key_requests', lazy='dynamic'))
    device_name = db.Column(db.String(255))
    expiry = db.Column(db.DateTime())
    created_api_key_id = db.Column(db.Integer, db.ForeignKey('api_key.id'))
    created_api_key = db.relationship('ApiKey')

    def __init__(self, user, device_name):
        self.token = generate_key()
        self.secret = generate_key(20)
        self.user = user
        self.device_name = device_name
        self.expiry = datetime.datetime.now() + datetime.timedelta(minutes=self.MINUTES_EXPIRY)

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __str__(self):
        return self.token

class PayDbTransactionSchema(Schema):
    token = fields.String()
    date = fields.String()
    timestamp = fields.Integer()
    action = fields.String()
    sender = fields.String()
    recipient = fields.String()
    amount = fields.Integer()
    attachment = fields.String()

class PayDbTransaction(db.Model):
    ACTION_ISSUE = "issue"
    ACTION_TRANSFER = "transfer"
    ACTION_DESTROY = "destroy"

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    date = db.Column(db.DateTime())
    action = db.Column(db.String(255), nullable=False)
    sender_token = db.Column(db.String(255), db.ForeignKey('user.token'), nullable=False)
    sender = db.relationship('User', foreign_keys=[sender_token], backref=db.backref('sent', lazy='dynamic'))
    recipient_token = db.Column(db.String(255), db.ForeignKey('user.token'), nullable=True)
    recipient = db.relationship('User', foreign_keys=[recipient_token], backref=db.backref('recieved', lazy='dynamic'))
    amount = db.Column(db.Integer())
    attachment = db.Column(db.String(255))

    def __init__(self, action, sender, recipient, amount, attachment):
        self.token = generate_key()
        self.date = datetime.datetime.now()
        self.action = action
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.attachment = attachment

    @property
    def timestamp(self):
        if not self.date:
            return 0
        return int(datetime.datetime.timestamp(self.date))

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def related_to_user(cls, session, user, offset, limit):
        # pylint: disable=no-member
        return session.query(cls).filter(or_(cls.sender_token == user.token, cls.recipient_token == user.token)).order_by(cls.id.desc()).offset(offset).limit(limit)

    @classmethod
    def all(cls, session):
        return session.query(cls).all()

    def __str__(self):
        return self.token

    def to_json(self):
        tx_schema = PayDbTransactionSchema()
        return tx_schema.dump(self)

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Setup base flask admin formatters

def date_format(view, value):
    return value.strftime('%Y.%m.%d %H:%M')

MY_DEFAULT_FORMATTERS = dict(typefmt.BASE_FORMATTERS)
MY_DEFAULT_FORMATTERS.update({
    datetime.date: date_format,
})

# Create customized model view classes
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

def format_date(self, context, model, name):
    if model.date:
        format_curdate = model.date
        return format_curdate.strftime('%Y.%m.%d %H:%M')
    return None

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

### define push notification models

class Topic(db.Model):
    __tablename__ = 'topics'
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String, nullable=False, unique=True)

    def __init__(self, topic):
        self.topic = topic

    @classmethod
    def topic_list(cls, session):
        return [row.topic for row in session.query(cls.topic)]

    @classmethod
    def from_name(cls, session, name):
        return session.query(cls).filter(cls.topic == name).first()

    def __repr__(self):
        return '<Topic %r %r>' % self.topic

### define key/value setting models

class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String, nullable=False, unique=True)
    value = db.Column(db.String, unique=False)

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return '<Setting %r %r>' % (self.key, self.value)

### define user models

class PayDbApiKeyModelView(BaseOnlyUserOwnedModelView):
    can_create = False
    can_delete = True
    can_edit = False
    column_list = ('token', 'device_name', 'expiry', 'permissions')
    column_labels = dict(token='API Key')

class PushNotificationLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fcm_registration_token = db.Column(db.String, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime(), nullable=False)

    def __init__(self, registration_token, latitude, longitude):
        self.fcm_registration_token = registration_token
        self.update(latitude, longitude)

    def update(self, latitude, longitude):
        self.latitude = latitude
        self.longitude = longitude
        self.date = datetime.datetime.now()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.fcm_registration_token == token).first()

    @classmethod
    def tokens_at_location(cls, session, latitude, max_lat_delta, longitude, max_long_delta, max_age_minutes):
        since = datetime.datetime.now() - datetime.timedelta(minutes=max_age_minutes)
        return session.query(cls).filter(and_(cls.date >= since, and_(and_(cls.latitude <= latitude + max_lat_delta, cls.latitude >= latitude - max_lat_delta), and_(cls.longitude <= longitude + max_long_delta, cls.longitude >= longitude - max_long_delta)))).all()

class PushNotificationLocationModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False

    def _format_location(view, context, model, name):
        lat = model.latitude
        lon = model.longitude

        # pylint: disable=duplicate-string-formatting-argument
        html = '''
        <a href="http://www.google.com/maps/place/{},{}">{}, {}</a>
        '''.format(lat, lon, lat, lon)
        return Markup(html)

    column_list = ['date', 'location', 'fcm_registration_token']
    column_formatters = {'location': _format_location}

class ReferralSchema(Schema):
    token = fields.String()
    date = fields.Date()
    recipient = fields.String()
    reward_sender_type = fields.String()
    reward_sender = fields.Integer()
    reward_recipient_type = fields.String()
    reward_recipient = fields.Integer()
    recipient_min_spend = fields.Integer()
    status = fields.String()

class Referral(db.Model):
    STATUS_CREATED = 'created'
    STATUS_CLAIMED = 'claimed'
    STATUS_DELETED = 'deleted'

    REWARD_TYPE_PERCENT = 'percent'
    REWARD_TYPE_FIXED = 'fixed'
    REWARD_TYPES_ALL = [REWARD_TYPE_PERCENT, REWARD_TYPE_FIXED]

    id = db.Column(db.Integer, primary_key=True)

    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('referrals', lazy='dynamic'))
    date = db.Column(db.DateTime(), nullable=False)
    recipient = db.Column(db.String, nullable=False)
    reward_sender_type = db.Column(db.String(255), nullable=False)
    reward_sender = db.Column(db.Integer, nullable=False)
    reward_recipient_type = db.Column(db.String(255), nullable=False)
    reward_recipient = db.Column(db.Integer, nullable=False)
    recipient_min_spend = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String, nullable=False)

    def __init__(self, user, recipient, reward_sender_type, reward_sender, reward_recipient_type, reward_recipient, recipient_min_spend):
        assert reward_sender_type == self.REWARD_TYPE_FIXED
        assert reward_recipient_type in self.REWARD_TYPES_ALL
        self.token = generate_key()
        self.user = user
        self.date = datetime.datetime.now()
        self.recipient = recipient
        self.reward_sender_type = reward_sender_type
        self.reward_sender = reward_sender
        self.reward_recipient_type = reward_recipient_type
        self.reward_recipient = reward_recipient
        self.recipient_min_spend = recipient_min_spend
        self.status = self.STATUS_CREATED

    def to_json(self):
        ref_schema = ReferralSchema()
        return ref_schema.dump(self)

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def from_token_user(cls, session, token, user):
        return session.query(cls).filter(and_(cls.token == token, cls.user_id == user.id)).first()

    @classmethod
    def from_user(cls, session, user):
        return session.query(cls).filter(cls.user_id == user.id).all()

class BrokerOrderSchema(Schema):
    token = fields.String()
    date = fields.DateTime()
    expiry = fields.DateTime()
    market = fields.String()
    side = fields.String()
    base_asset = fields.Method('get_base_asset')
    base_amount = fields.Integer()
    base_amount_dec = fields.Method('get_base_amount_dec')
    quote_asset = fields.Method('get_quote_asset')
    quote_amount = fields.Integer()
    quote_amount_dec = fields.Method('get_quote_amount_dec')
    recipient = fields.String()
    status = fields.String()
    payment_url = fields.Method('get_payment_url')

    def get_base_asset(self, obj):
        base_asset, _ = dasset.assets_from_market(obj.market)
        return base_asset

    def get_quote_asset(self, obj):
        _, quote_asset = dasset.assets_from_market(obj.market)
        return quote_asset

    def get_base_amount_dec(self, obj):
        base_asset, _ = dasset.assets_from_market(obj.market)
        return str(dasset.asset_int_to_dec(base_asset, obj.base_amount))

    def get_quote_amount_dec(self, obj):
        _, quote_asset = dasset.assets_from_market(obj.market)
        return str(dasset.asset_int_to_dec(quote_asset, obj.quote_amount))

    def get_payment_url(self, obj):
        payment_url = None
        if obj.windcave_payment_request:
            payment_url = url_for('payments.payment_interstitial', token=obj.windcave_payment_request.token, _external=True)
        return payment_url

class BrokerOrder(db.Model):
    STATUS_CREATED = 'created'
    STATUS_READY = 'ready'
    STATUS_INCOMING = 'incoming'
    STATUS_CONFIRMED = 'confirmed'
    STATUS_EXCHANGE = 'exchange'
    STATUS_WITHDRAW = 'withdraw'
    STATUS_COMPLETED = 'completed'
    STATUS_EXPIRED = 'expired'
    STATUS_CANCELLED = 'cancelled'

    MINUTES_EXPIRY = 15

    id = db.Column(db.Integer, primary_key=True)

    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('orders', lazy='dynamic'))
    date = db.Column(db.DateTime(), nullable=False)
    expiry = db.Column(db.DateTime(), nullable=False)
    market = db.Column(db.String, nullable=False)
    side = db.Column(db.String, nullable=False)
    base_amount = db.Column(db.Integer, nullable=False)
    quote_amount = db.Column(db.Integer, nullable=False)
    recipient = db.Column(db.String, nullable=False)
    windcave_payment_request_id = db.Column(db.Integer, db.ForeignKey('windcave_payment_request.id'))
    windcave_payment_request = db.relationship('WindcavePaymentRequest', backref=db.backref('broker_order', uselist=False))
    exchange_order_id = db.Column(db.Integer, db.ForeignKey('exchange_order.id'))
    exchange_order = db.relationship('ExchangeOrder')
    exchange_withdrawal_id = db.Column(db.Integer, db.ForeignKey('exchange_withdrawal.id'))
    exchange_withdrawal = db.relationship('ExchangeWithdrawal', backref=db.backref('broker_order', uselist=False))
    status = db.Column(db.String, nullable=False)

    def __init__(self, user, market, side, base_amount, quote_amount, recipient):
        self.token = generate_key()
        self.user = user
        self.date = datetime.datetime.now()
        self.expiry = datetime.datetime.now() + datetime.timedelta(minutes=self.MINUTES_EXPIRY)
        self.market = market
        self.side = side
        self.base_amount = base_amount
        self.quote_amount = quote_amount
        self.recipient = recipient
        self.status = self.STATUS_CREATED

    def to_json(self):
        ref_schema = BrokerOrderSchema()
        return ref_schema.dump(self)

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def from_user(cls, session, user, offset, limit):
        # pylint: disable=no-member
        return session.query(cls).filter(cls.user_id == user.id).order_by(cls.id.desc()).offset(offset).limit(limit)

    @classmethod
    def all_active(cls, session):
        return session.query(cls).filter(and_(cls.status != cls.STATUS_COMPLETED, and_(cls.status != cls.STATUS_EXPIRED, cls.status != cls.STATUS_CANCELLED))).all()

class ExchangeOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    date = db.Column(db.DateTime(), nullable=False)
    exchange_reference = db.Column(db.String, nullable=False)

    def __init__(self, exchange_reference):
        self.token = generate_key()
        self.date = datetime.datetime.now()
        self.exchange_reference = exchange_reference

class ExchangeWithdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    date = db.Column(db.DateTime(), nullable=False)
    exchange_reference = db.Column(db.String, nullable=False)

    def __init__(self, exchange_reference):
        self.token = generate_key()
        self.date = datetime.datetime.now()
        self.exchange_reference = exchange_reference

class WindcavePaymentRequestSchema(Schema):
    date = fields.DateTime()
    token = fields.String()
    asset = fields.String()
    amount = fields.Integer()
    windcave_session_id = fields.String()
    windcave_status = fields.String()
    windcave_authorised = fields.Boolean()
    windcave_allow_retry = fields.Boolean()
    status = fields.String()

class WindcavePaymentRequest(db.Model):
    STATUS_CREATED = 'created'
    STATUS_COMPLETED = 'completed'
    STATUS_CANCELLED = 'cancelled'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False, unique=False)
    token = db.Column(db.String, nullable=False, unique=True)
    asset = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    windcave_session_id = db.Column(db.String)
    windcave_status = db.Column(db.String)
    windcave_authorised = db.Column(db.Boolean)
    windcave_allow_retry = db.Column(db.Boolean)
    status = db.Column(db.String)

    def __init__(self, token, asset, amount, windcave_session_id, windcave_status):
        self.date = datetime.datetime.now()
        self.token = token
        self.asset = asset
        self.amount = amount
        self.windcave_session_id = windcave_session_id
        self.windcave_status = windcave_status
        self.status = self.STATUS_CREATED

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __repr__(self):
        return '<WindcavePaymentRequest %r>' % (self.token)

    def to_json(self):
        schema = WindcavePaymentRequestSchema()
        return schema.dump(self)

class PayoutRequestSchema(Schema):
    date = fields.DateTime()
    token = fields.String()
    asset = fields.String()
    amount = fields.Integer()
    sender = fields.String()
    sender_account = fields.String()
    sender_reference = fields.String()
    sender_code = fields.String()
    receiver = fields.String()
    receiver_account = fields.String()
    receiver_reference = fields.String()
    receiver_code = fields.String()
    receiver_particulars = fields.String()
    email = fields.String()
    email_sent = fields.Boolean()
    processed = fields.Boolean()
    status = fields.String()

class PayoutGroupRequest(db.Model):
    payout_group_id = db.Column(db.Integer, db.ForeignKey('payout_group.id'), primary_key=True)
    payout_request_id = db.Column(db.Integer, db.ForeignKey('payout_request.id'), primary_key=True)

    def __init__(self, group, req):
        self.payout_group_id = group.id
        self.payout_request_id = req.id

class PayoutRequest(db.Model):
    STATUS_CREATED = 'created'
    STATUS_COMPLETED = 'completed'
    STATUS_SUSPENDED = 'suspended'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False, unique=False)
    token = db.Column(db.String, nullable=False, unique=True)
    secret = db.Column(db.String, nullable=False)
    asset = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    sender = db.Column(db.String, nullable=False)
    sender_account = db.Column(db.String, nullable=False)
    sender_reference = db.Column(db.String, nullable=False)
    sender_code = db.Column(db.String, nullable=False)
    receiver = db.Column(db.String, nullable=False)
    receiver_account = db.Column(db.String, nullable=False)
    receiver_reference = db.Column(db.String, nullable=False)
    receiver_code = db.Column(db.String, nullable=False)
    receiver_particulars = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    email_sent = db.Column(db.Boolean)
    processed = db.Column(db.Boolean)
    status = db.Column(db.String)
    groups = db.relationship('PayoutGroup', secondary='payout_group_request', back_populates='requests')

    def __init__(self, asset, amount, sender, sender_account, sender_reference, sender_code, receiver, receiver_account, receiver_reference, receiver_code, receiver_particulars, email, email_sent):
        self.date = datetime.datetime.now()
        self.token = generate_key()
        self.secret = generate_key(20)
        self.asset = asset
        self.amount = amount
        self.sender = sender
        self.sender_account = sender_account
        self.sender_reference = sender_reference
        self.sender_code = sender_code
        self.receiver = receiver
        self.receiver_account = receiver_account
        self.receiver_reference = receiver_reference
        self.receiver_code = receiver_code
        self.receiver_particulars = receiver_particulars
        self.email = email
        self.email_sent = email_sent
        self.processed = False
        self.status = self.STATUS_CREATED

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def not_processed(cls, session):
        return session.query(cls).filter(cls.processed is False).all()

    @classmethod
    def where_status_processed(cls, session):
        return session.query(cls).filter(cls.status == 'processed')

    def __repr__(self):
        return '<PayoutRequest %r>' % (self.token)

    def to_json(self):
        schema = PayoutRequestSchema()
        return schema.dump(self)

class PayoutGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String, nullable=False, unique=True)
    secret = db.Column(db.String, nullable=False, unique=True)
    expired = db.Column(db.Boolean, nullable=False)
    requests = db.relationship('PayoutRequest', secondary='payout_group_request', back_populates='groups')

    def __init__(self):
        self.token = generate_key()
        self.secret = generate_key(20)
        self.expired = False

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def expire_all_but(cls, session, group):
        session.query(cls).filter(cls.id != group.id).update({"expired": True})

class AplyId(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String, nullable=False, unique=True)
    kyc_request_id = db.Column(db.Integer, db.ForeignKey('kyc_request.id'))
    kyc_request = db.relationship("KycRequest", back_populates="aplyid")

    def __init__(self, kyc_request, transaction_id):
        self.kyc_request = kyc_request
        self.transaction_id = transaction_id

class KycRequestSchema(Schema):
    date = fields.DateTime()
    token = fields.String()
    status = fields.String()

class KycRequest(db.Model):
    STATUS_CREATED = 'created'
    STATUS_COMPLETED = 'completed'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False, unique=False)
    token = db.Column(db.String, nullable=False, unique=True)
    status = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('kyc_requests', lazy='dynamic'))
    aplyid = db.relationship("AplyId", uselist=False, back_populates="kyc_request")

    def __init__(self, user):
        self.user = user
        self.date = datetime.datetime.now()
        self.token = generate_key()
        self.status = self.STATUS_CREATED

    def validated(self):
        return self.status == self.STATUS_COMPLETED

    def url(self):
        return url_for('kyc.request_start', token=self.token, _external=True)

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __repr__(self):
        return '<KycRequest %r>' % (self.token)

    def to_json(self):
        schema = KycRequestSchema()
        return schema.dump(self).data
