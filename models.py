# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-arguments
# pylint: disable=too-few-public-methods

from datetime import datetime, timedelta
import logging

from flask import url_for
from flask_security import UserMixin, RoleMixin
from marshmallow import Schema, fields
from sqlalchemy import and_, exists

from app_core import db
from utils import generate_key
import assets
from assets import market_side_is, MarketSide

logger = logging.getLogger(__name__)

#
# Define beryllium models
#

class FromTokenMixin():
    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

class FromUserMixin():
    @classmethod
    def from_user(cls, session, user, offset, limit):
        # pylint: disable=no-member
        return session.query(cls).filter(cls.user_id == user.id).order_by(cls.id.desc()).offset(offset).limit(limit)

    @classmethod
    def total_for_user(cls, session, user):
        # pylint: disable=no-member
        return session.query(cls).filter(cls.user_id == user.id).count()

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    ROLE_ADMIN = 'admin'
    ROLE_FINANCE = 'finance'
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

    dasset_subaccount = db.relationship('DassetSubaccount', uselist=False, back_populates='user')

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

class UserCreateRequest(db.Model, FromTokenMixin):

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
        self.expiry = datetime.now() + timedelta(minutes=self.MINUTES_EXPIRY)

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    def __str__(self):
        return self.email

class UserUpdateEmailRequest(db.Model, FromTokenMixin):

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
        self.expiry = datetime.now() + timedelta(minutes=self.MINUTES_EXPIRY)

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

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

class ApiKey(db.Model, FromTokenMixin):
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
        self.expiry = datetime.now() + timedelta(minutes=self.MINUTES_EXPIRY)

    def has_permission(self, permission_name):
        perm = Permission.from_name(db.session, permission_name)
        if perm:
            return perm in self.permissions # pylint: disable=unsupported-membership-test
        return False

class ApiKeyRequest(db.Model, FromTokenMixin):
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
        self.expiry = datetime.now() + timedelta(minutes=self.MINUTES_EXPIRY)

    def __str__(self):
        return self.token

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
        return f'<Topic {self.topic}>'

class PushNotificationLocation(db.Model, FromTokenMixin):
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
        self.date = datetime.now()

    @classmethod
    def tokens_at_location(cls, session, latitude, max_lat_delta, longitude, max_long_delta, max_age_minutes):
        since = datetime.now() - timedelta(minutes=max_age_minutes)
        return session.query(cls).filter(and_(cls.date >= since, and_(and_(cls.latitude <= latitude + max_lat_delta, cls.latitude >= latitude - max_lat_delta), and_(cls.longitude <= longitude + max_long_delta, cls.longitude >= longitude - max_long_delta)))).all()

class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String, nullable=False, unique=True)
    value = db.Column(db.String, unique=False)

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return f'<Setting {self.key} {self.value}>'

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

class Referral(db.Model, FromTokenMixin, FromUserMixin):
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
        self.date = datetime.now()
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
    def from_token_user(cls, session, token, user):
        return session.query(cls).filter(and_(cls.token == token, cls.user_id == user.id)).first()

class BrokerOrderSchema(Schema):
    token = fields.String()
    date = fields.DateTime()
    expiry = fields.DateTime()
    market = fields.String()
    side = fields.String()
    base_asset = fields.String()
    base_amount = fields.Integer()
    base_amount_dec = fields.Method('get_base_amount_dec')
    quote_asset = fields.String()
    quote_amount = fields.Integer()
    quote_amount_dec = fields.Method('get_quote_amount_dec')
    recipient = fields.String()
    address = fields.String()
    status = fields.String()
    payment_url = fields.Method('get_payment_url')

    def get_base_amount_dec(self, obj):
        return str(assets.asset_int_to_dec(obj.base_asset, obj.base_amount))

    def get_quote_amount_dec(self, obj):
        return str(assets.asset_int_to_dec(obj.quote_asset, obj.quote_amount))

    def get_payment_url(self, obj):
        payment_url = None
        if obj.windcave_payment_request:
            payment_url = url_for('payments.payment_interstitial', token=obj.windcave_payment_request.token, _external=True)
        if obj.address:
            if market_side_is(obj.side, MarketSide.BID):
                payment_url = assets.crypto_uri(obj.quote_asset, obj.address, obj.quote_amount)
            else:
                payment_url = assets.crypto_uri(obj.base_asset, obj.address, obj.base_amount)
        return payment_url

class BrokerOrder(db.Model, FromUserMixin, FromTokenMixin):
    STATUS_CREATED = 'created'
    STATUS_READY = 'ready'
    STATUS_INCOMING = 'incoming'
    STATUS_CONFIRMED = 'confirmed'
    STATUS_EXCHANGE = 'exchanging'
    STATUS_WITHDRAW = 'withdrawing'
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
    base_asset = db.Column(db.String, nullable=False)
    quote_asset = db.Column(db.String, nullable=False)
    base_amount = db.Column(db.BigInteger, nullable=False)
    quote_amount = db.Column(db.BigInteger, nullable=False)
    recipient = db.Column(db.String, nullable=False)
    windcave_payment_request_id = db.Column(db.Integer, db.ForeignKey('windcave_payment_request.id'))
    windcave_payment_request = db.relationship('WindcavePaymentRequest', backref=db.backref('broker_order', uselist=False))
    payout_request_id = db.Column(db.Integer, db.ForeignKey('payout_request.id'))
    payout_request = db.relationship('PayoutRequest', backref=db.backref('broker_order', uselist=False))
    exchange_order_id = db.Column(db.Integer, db.ForeignKey('exchange_order.id'))
    exchange_order = db.relationship('ExchangeOrder')
    crypto_withdrawal_id = db.Column(db.Integer, db.ForeignKey('crypto_withdrawal.id'))
    crypto_withdrawal = db.relationship('CryptoWithdrawal', backref=db.backref('broker_order', uselist=False))
    crypto_deposit_id = db.Column(db.Integer, db.ForeignKey('crypto_deposit.id'))
    crypto_deposit = db.relationship('CryptoDeposit', backref=db.backref('broker_order', uselist=False))
    address = db.Column(db.String)

    status = db.Column(db.String, nullable=False)

    def __init__(self, user, market, side, base_asset, quote_asset, base_amount, quote_amount, recipient):
        self.token = generate_key()
        self.user = user
        self.date = datetime.now()
        self.expiry = datetime.now() + timedelta(minutes=self.MINUTES_EXPIRY)
        self.market = market
        self.side = side
        self.base_asset = base_asset
        self.quote_asset = quote_asset
        self.base_amount = base_amount
        self.quote_amount = quote_amount
        self.recipient = recipient
        self.status = self.STATUS_CREATED

    def to_json(self):
        ref_schema = BrokerOrderSchema()
        return ref_schema.dump(self)

    @classmethod
    def all_active(cls, session):
        return session.query(cls).filter(and_(cls.status != cls.STATUS_COMPLETED, and_(cls.status != cls.STATUS_EXPIRED, cls.status != cls.STATUS_CANCELLED))).all()

class DassetSubaccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False, unique=False)
    subaccount_id = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', uselist=False, back_populates='dasset_subaccount')

    def __init__(self, user, subaccount_id):
        self.user = user
        self.date = datetime.now()
        self.subaccount_id = subaccount_id

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_subaccount_id(cls, session, subaccount_id):
        return session.query(cls).filter(cls.subaccount_id == subaccount_id).first()

    def __repr__(self):
        return f'<DassetSubaccount {self.subaccount_id}>'

class ExchangeOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    date = db.Column(db.DateTime(), nullable=False)
    exchange_reference = db.Column(db.String, nullable=False)

    def __init__(self, exchange_reference):
        self.token = generate_key()
        self.date = datetime.now()
        self.exchange_reference = exchange_reference

class CryptoWithdrawal(db.Model, FromUserMixin):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('crypto_withdrawals', lazy='dynamic'))
    date = db.Column(db.DateTime(), nullable=False)
    asset = db.Column(db.String, nullable=False)
    amount = db.Column(db.BigInteger, nullable=False)
    exchange_reference = db.Column(db.String, nullable=False)
    txid = db.Column(db.String)

    def __init__(self, user, asset, amount, exchange_reference):
        self.token = generate_key()
        self.user = user
        self.date = datetime.now()
        self.asset = asset
        self.amount = amount
        self.exchange_reference = exchange_reference

class CryptoDepositSchema(Schema):
    token = fields.String()
    date = fields.DateTime()
    asset = fields.String()
    amount = fields.Integer()
    amount_dec = fields.Method('get_amount_dec')
    txid = fields.String()
    confirmed = fields.Boolean()

    def get_amount_dec(self, obj):
        return str(assets.asset_int_to_dec(obj.asset, obj.amount))

class CryptoDeposit(db.Model, FromUserMixin):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('crypto_deposits', lazy='dynamic'))
    crypto_address_id = db.Column(db.Integer, db.ForeignKey('crypto_address.id'), nullable=False)
    crypto_address = db.relationship('CryptoAddress', backref=db.backref('crypto_deposits', lazy='dynamic'))
    date = db.Column(db.DateTime(), nullable=False)
    asset = db.Column(db.String, nullable=False)
    amount = db.Column(db.BigInteger, nullable=False)
    exchange_reference = db.Column(db.String, nullable=False)
    txid = db.Column(db.String(255), unique=True, nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False)

    def __init__(self, user, asset, amount, exchange_reference, txid, confirmed):
        self.token = generate_key()
        self.user = user
        self.date = datetime.now()
        self.asset = asset
        self.amount = amount
        self.exchange_reference = exchange_reference
        self.txid = txid
        self.confirmed = confirmed

    def to_json(self):
        ref_schema = CryptoDepositSchema()
        return ref_schema.dump(self)

    @classmethod
    def from_txid(cls, session, txid):
        return session.query(cls).filter(cls.txid == txid).first()

    @classmethod
    def not_in_broker_orders(cls, session, asset, amount):
        session.query(cls).filter(cls.asset == asset).filter(cls.amount == amount) \
            .filter(~exists().where(BrokerOrder.crypto_deposit_id == cls.id)).all()

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

class WindcavePaymentRequest(db.Model, FromTokenMixin):
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
        self.date = datetime.now()
        self.token = token
        self.asset = asset
        self.amount = amount
        self.windcave_session_id = windcave_session_id
        self.windcave_status = windcave_status
        self.status = self.STATUS_CREATED

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    def __repr__(self):
        return f'<WindcavePaymentRequest {self.token}>'

    def to_json(self):
        schema = WindcavePaymentRequestSchema()
        return schema.dump(self)

class PayoutGroupRequest(db.Model):
    payout_group_id = db.Column(db.Integer, db.ForeignKey('payout_group.id'), primary_key=True)
    payout_request_id = db.Column(db.Integer, db.ForeignKey('payout_request.id'), primary_key=True)

    def __init__(self, group, req):
        self.payout_group_id = group.id
        self.payout_request_id = req.id

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
    status = fields.String()

class PayoutRequest(db.Model, FromTokenMixin):
    STATUS_CREATED = 'created'
    STATUS_COMPLETED = 'completed'
    STATUS_SUSPENDED = 'suspended'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False, unique=False)
    token = db.Column(db.String, nullable=False, unique=True)
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
    status = db.Column(db.String)
    groups = db.relationship('PayoutGroup', secondary='payout_group_request', back_populates='requests')

    def __init__(self, asset, amount, sender, sender_account, sender_reference, sender_code, receiver, receiver_account, receiver_reference, receiver_code, receiver_particulars, email, email_sent):
        self.date = datetime.now()
        self.token = generate_key()
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
        self.status = self.STATUS_CREATED

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def where_status_created(cls, session):
        return session.query(cls).filter(cls.status == cls.STATUS_CREATED).all()

    @classmethod
    def where_status_suspended(cls, session):
        return session.query(cls).filter(cls.status == cls.STATUS_SUSPENDED).all()

    @classmethod
    def not_completed(cls, session):
        return session.query(cls).filter(cls.status != cls.STATUS_COMPLETED)

    def __repr__(self):
        return f'<PayoutRequest {self.token}>'

    def to_json(self):
        schema = PayoutRequestSchema()
        return schema.dump(self)

class PayoutGroup(db.Model, FromTokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String, nullable=False, unique=True)
    expired = db.Column(db.Boolean, nullable=False)
    requests = db.relationship('PayoutRequest', secondary='payout_group_request', back_populates='groups')

    def __init__(self):
        self.token = generate_key()
        self.expired = False

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

class KycRequest(db.Model, FromTokenMixin):
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
        self.date = datetime.now()
        self.token = generate_key()
        self.status = self.STATUS_CREATED

    def validated(self):
        return self.status == self.STATUS_COMPLETED

    def url(self):
        return url_for('kyc.request_start', token=self.token, _external=True)

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    def __repr__(self):
        return f'<KycRequest {self.token}>'

    def to_json(self):
        schema = KycRequestSchema()
        return schema.dump(self)

class AddressBookSchema(Schema):
    date = fields.DateTime()
    token = fields.String()
    asset = fields.String()
    recipient = fields.String()
    description = fields.String()

class AddressBook(db.Model, FromTokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False, unique=False)
    token = db.Column(db.String, nullable=False, unique=True)
    asset = db.Column(db.String, nullable=False)
    recipient = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('address_book_entries', lazy='dynamic'))

    def __init__(self, user, asset, recipient, description):
        self.user = user
        self.date = datetime.now()
        self.token = generate_key()
        self.asset = asset
        self.recipient = recipient
        self.description = description

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_recipient(cls, session, user, asset, recipient):
        return session.query(cls).filter(and_(cls.user_id == user.id, and_(cls.asset == asset, cls.recipient == recipient))).first()

    @classmethod
    def of_asset(cls, session, user, asset):
        return session.query(cls).filter(and_(cls.user_id == user.id, cls.asset == asset)).all()

    def to_json(self):
        schema = AddressBookSchema()
        return schema.dump(self)

class FiatDbTransactionSchema(Schema):
    user = fields.String()
    token = fields.String()
    date = fields.String()
    timestamp = fields.Integer()
    action = fields.String()
    asset = fields.String()
    amount = fields.Integer()
    attachment = fields.String()

class FiatDbTransaction(db.Model, FromTokenMixin):
    ACTION_CREDIT = 'credit'
    ACTION_DEBIT = 'debit'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('fiatdb_transactions', lazy='dynamic'))
    token = db.Column(db.String(255), unique=True, nullable=False)
    date = db.Column(db.DateTime())
    action = db.Column(db.String(255), nullable=False)
    asset = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Integer())
    attachment = db.Column(db.String(255))

    def __init__(self, user, action, asset, amount, attachment):
        self.user = user
        self.token = generate_key()
        self.date = datetime.now()
        self.action = action
        self.asset = asset
        self.amount = amount
        self.attachment = attachment

    @classmethod
    def all(cls, session):
        return session.query(cls).all()

    def __str__(self):
        return self.token

    def to_json(self):
        tx_schema = FiatDbTransactionSchema()
        return tx_schema.dump(self)

class FiatDepositSchema(Schema):
    token = fields.String()
    date = fields.DateTime()
    expiry = fields.DateTime()
    asset = fields.String()
    amount = fields.Integer()
    amount_dec = fields.Method('get_amount_dec')
    status = fields.String()
    payment_url = fields.Method('get_payment_url')

    def get_amount_dec(self, obj):
        return str(assets.asset_int_to_dec(obj.asset, obj.amount))

    def get_payment_url(self, obj):
        payment_url = None
        if obj.windcave_payment_request:
            payment_url = url_for('payments.payment_interstitial', token=obj.windcave_payment_request.token, _external=True)
        return payment_url

class FiatDeposit(db.Model, FromUserMixin, FromTokenMixin):
    STATUS_CREATED = 'created'
    STATUS_COMPLETED = 'completed'
    STATUS_EXPIRED = 'expired'
    STATUS_CANCELLED = 'cancelled'

    MINUTES_EXPIRY = 15

    id = db.Column(db.Integer, primary_key=True)

    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('fiat_deposits', lazy='dynamic'))
    date = db.Column(db.DateTime(), nullable=False)
    expiry = db.Column(db.DateTime(), nullable=False)
    asset = db.Column(db.String, nullable=False)
    amount = db.Column(db.BigInteger, nullable=False)
    windcave_payment_request_id = db.Column(db.Integer, db.ForeignKey('windcave_payment_request.id'))
    windcave_payment_request = db.relationship('WindcavePaymentRequest', backref=db.backref('fiat_deposit', uselist=False))

    status = db.Column(db.String, nullable=False)

    def __init__(self, user, asset, amount):
        self.token = generate_key()
        self.user = user
        self.date = datetime.now()
        self.expiry = datetime.now() + timedelta(minutes=self.MINUTES_EXPIRY)
        self.asset = asset
        self.amount = amount
        self.status = self.STATUS_CREATED

    def to_json(self):
        ref_schema = FiatDepositSchema()
        return ref_schema.dump(self)

    @classmethod
    def all_active(cls, session):
        return session.query(cls).filter(and_(cls.status != cls.STATUS_COMPLETED, and_(cls.status != cls.STATUS_EXPIRED, cls.status != cls.STATUS_CANCELLED))).all()

class FiatWithdrawalSchema(Schema):
    token = fields.String()
    date = fields.DateTime()
    asset = fields.String()
    amount = fields.Integer()
    amount_dec = fields.Method('get_amount_dec')
    recipient = fields.String()
    status = fields.String()

    def get_amount_dec(self, obj):
        return str(assets.asset_int_to_dec(obj.asset, obj.amount))

class FiatWithdrawal(db.Model, FromUserMixin, FromTokenMixin):
    STATUS_CREATED = 'created'
    STATUS_COMPLETED = 'completed'
    STATUS_CANCELLED = 'cancelled'

    id = db.Column(db.Integer, primary_key=True)

    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('fiat_withdrawals', lazy='dynamic'))
    date = db.Column(db.DateTime(), nullable=False)
    asset = db.Column(db.String, nullable=False)
    amount = db.Column(db.BigInteger, nullable=False)
    recipient = db.Column(db.String, nullable=False)
    payout_request_id = db.Column(db.Integer, db.ForeignKey('payout_request.id'))
    payout_request = db.relationship('PayoutRequest', backref=db.backref('fiat_withdrawal', uselist=False))

    status = db.Column(db.String, nullable=False)

    def __init__(self, user, asset, amount, recipient):
        self.token = generate_key()
        self.user = user
        self.date = datetime.now()
        self.asset = asset
        self.amount = amount
        self.recipient = recipient
        self.status = self.STATUS_CREATED

    def to_json(self):
        ref_schema = FiatWithdrawalSchema()
        return ref_schema.dump(self)

    @classmethod
    def all_active(cls, session):
        return session.query(cls).filter(and_(cls.status != cls.STATUS_COMPLETED, cls.status != cls.STATUS_CANCELLED)).all()

class CryptoAddress(db.Model, FromUserMixin):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('crypto_addresses', lazy='dynamic'))
    asset = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255), unique=True, nullable=False)
    date = db.Column(db.DateTime(), nullable=False)
    # we make these integer timestamps so we dont have any issues with any comparisons in DB
    viewed_at = db.Column(db.BigInteger(), nullable=False)
    checked_at = db.Column(db.BigInteger(), nullable=False)

    def __init__(self, user, asset, address):
        self.user = user
        self.asset = asset
        self.address = address
        self.date = datetime.now()
        self.viewed_at = 0
        self.checked_at = 0

    @classmethod
    def from_asset(cls, session, user, asset):
        return session.query(cls).filter(and_(cls.user_id == user.id, cls.asset == asset)).first()

    @classmethod
    def from_addr(cls, session, addr):
        return session.query(cls).filter(cls.address == addr).first()

    @classmethod
    def need_to_be_checked(cls, session):
        now = datetime.timestamp(datetime.now())
        return session.query(cls).filter(now - cls.checked_at > (cls.checked_at - cls.viewed_at) * 2).all()
