# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-arguments
# pylint: disable=no-self-argument
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-locals
# pylint: disable=too-many-lines

import time
import datetime
import decimal
import csv
import logging
import json
import secrets

from flask import redirect, url_for, request, flash, has_app_context, g, abort
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, current_user
from flask_admin import expose
from flask_admin.babel import lazy_gettext
from flask_admin.helpers import get_form_data
from flask_admin.contrib import sqla
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from flask_admin.model import filters, typefmt
from wtforms.fields import TextField, DecimalField, FileField
from wtforms import validators
from marshmallow import Schema, fields
from markupsafe import Markup
from sqlalchemy import or_, and_
from sqlalchemy.exc import SQLAlchemyError, DBAPIError

from app_core import app, db
from utils import generate_key, is_email, is_mobile, is_address, sha256

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
    ROLE_PROPOSER = 'proposer'
    ROLE_AUTHORIZER = 'authorizer'
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
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
    current_login_ip = db.Column(db.String(100))
    login_count = db.Column(db.Integer)
    active = db.Column(db.Boolean())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    photo = db.Column(db.String())
    photo_type = db.Column(db.String(255))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.token = secrets.token_urlsafe(8)

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
    photo = db.Column(db.String())
    photo_type = db.Column(db.String(255))
    password = db.Column(db.String(255))
    expiry = db.Column(db.DateTime())

    def __init__(self, first_name, last_name, email, photo, photo_type, password):
        self.token = secrets.token_urlsafe(8)
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.photo = photo
        self.photo_type = photo_type
        self.password = password
        self.expiry = datetime.datetime.now() + datetime.timedelta(self.MINUTES_EXPIRY)

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
        self.token = secrets.token_urlsafe(8)
        self.user = user
        self.email = email
        self.expiry = datetime.datetime.now() + datetime.timedelta(self.MINUTES_EXPIRY)

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
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    secret = db.Column(db.String(255), nullable=False)
    nonce = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('api_keys', lazy='dynamic'))
    device_name = db.Column(db.String(255))
    expiry = db.Column(db.DateTime())
    permissions = db.relationship('Permission', secondary=permissions_api_keys,
                            backref=db.backref('api_keys', lazy='dynamic'))

    def __init__(self, user, device_name):
        self.user_id = user.id
        self.token = secrets.token_urlsafe(8)
        self.secret = secrets.token_urlsafe(16)
        self.nonce = 0
        self.device_name = device_name
        self.expiry = datetime.datetime.now() + datetime.timedelta(30)

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
        self.token = secrets.token_urlsafe(8)
        self.secret = secrets.token_urlsafe(16)
        self.user = user
        self.device_name = device_name
        self.expiry = datetime.datetime.now() + datetime.timedelta(self.MINUTES_EXPIRY)

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __str__(self):
        return self.token

class PayDbTransactionSchema(Schema):
    token = fields.String()
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
    timestamp = db.Column(db.Integer)
    action = db.Column(db.String(255), nullable=False)
    sender_token = db.Column(db.String(255), db.ForeignKey('user.token'), nullable=False)
    sender = db.relationship('User', foreign_keys=[sender_token], backref=db.backref('sent', lazy='dynamic'))
    recipient_token = db.Column(db.String(255), db.ForeignKey('user.token'), nullable=True)
    recipient = db.relationship('User', foreign_keys=[recipient_token], backref=db.backref('recieved', lazy='dynamic'))
    amount = db.Column(db.Integer())
    attachment = db.Column(db.String(255))

    def __init__(self, action, sender, recipient, amount, attachment):
        self.token = secrets.token_urlsafe(8)
        self.timestamp = int(time.time())
        self.action = action
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.attachment = attachment

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def related_to_user(cls, session, user, offset, limit):
        return session.query(cls).filter(or_(cls.sender_token == user.token, cls.recipient_token == user.token)).order_by(cls.id.desc()).offset(offset).limit(limit)

    @classmethod
    def all(cls, session):
        return session.query(cls).all()

    def __str__(self):
        return self.token

    def to_json(self):
        tx_schema = PayDbTransactionSchema()
        return tx_schema.dump(self).data

class Payment(db.Model):
    STATE_CREATED = "created"
    STATE_SENT_CLAIM_LINK = "sent_claim_link"
    STATE_EXPIRED = "expired"
    STATE_SENT_FUNDS = "sent_funds"

    id = db.Column(db.Integer, primary_key=True)
    proposal_id = db.Column(db.Integer, db.ForeignKey('proposal.id'), nullable=False)
    proposal = db.relationship('Proposal', backref=db.backref('payments', lazy='dynamic'))
    token = db.Column(db.String(255), unique=True, nullable=False)
    mobile = db.Column(db.String(255))
    email = db.Column(db.String(255))
    recipient = db.Column(db.String(255))
    message = db.Column(db.String())
    amount = db.Column(db.Integer)
    status = db.Column(db.String(255))
    txid = db.Column(db.String(255))

    def __init__(self, proposal, mobile, email, recipient, message, amount):
        self.proposal = proposal
        self.token = generate_key(8)
        self.mobile = mobile
        self.email = email
        self.recipient = recipient
        self.message = message
        self.amount = amount
        self.status = self.STATE_CREATED
        self.txid = None

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __repr__(self):
        return "<Payment %r>" % (self.token)

categories_proposals = db.Table(
    'categories_proposals',
    db.Column('proposal_id', db.Integer(), db.ForeignKey('proposal.id')),
    db.Column('category_id', db.Integer(), db.ForeignKey('category.id'))
)

class Category(db.Model):
    CATEGORY_MARKETING = 'marketing'
    CATEGORY_MISC = 'misc'
    CATEGORY_TESTING = 'testing'
    CATEGORY_REFERRAL = 'referral'

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    @classmethod
    def from_name(cls, session, name):
        return session.query(cls).filter(cls.name == name).first()

    def __str__(self):
        return f'{self.name}'

class Proposal(db.Model):
    STATE_CREATED = "created"
    STATE_AUTHORIZED = "authorized"
    STATE_DECLINED = "declined"
    STATE_EXPIRED = "expired"

    HOURS_EXPIRY = 72

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(), nullable=False)
    proposer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    proposer = db.relationship('User', foreign_keys=[proposer_id], backref=db.backref('proposals', lazy='dynamic'))
    reason = db.Column(db.String())
    authorizer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    authorizer = db.relationship('User', foreign_keys=[authorizer_id], backref=db.backref('proposals_authorized', lazy='dynamic'))
    date_authorized = db.Column(db.DateTime())
    date_expiry = db.Column(db.DateTime())
    status = db.Column(db.String(255))
    categories = db.relationship('Category', secondary=categories_proposals,
                            backref=db.backref('proposals', lazy='dynamic'))

    def __init__(self, proposer, reason):
        self.generate_defaults()
        self.proposer = proposer
        self.reason = reason

    def generate_defaults(self):
        self.date = datetime.datetime.now()
        self.authorizer = None
        self.date_authorized = None
        self.date_expiry = None
        self.status = self.STATE_CREATED

    def authorize(self, user):
        if self.status == Proposal.STATE_CREATED:
            self.status = Proposal.STATE_AUTHORIZED
            now = datetime.datetime.now()
            self.date_authorized = now
            self.date_expiry = now + datetime.timedelta(hours = Proposal.HOURS_EXPIRY)
            self.authorizer = user

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def in_status(cls, session, status):
        return session.query(cls).filter(cls.status == status).all()

    def __repr__(self):
        return "<Proposal %r>" % (self.id)

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
                current_user.has_role(Role.ROLE_ADMIN))

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

def validate_recipient(recipient):
    if not recipient or \
       (not is_email(recipient) and not is_mobile(recipient) and not is_address(recipient)):
        return False
    ##TODO: direct wallet address not yet implemented
    if is_address(recipient):
        return False
    return True

def validate_csv(data):
    rows = []
    try:
        data = data.decode('utf-8')
    except: # pylint: disable=bare-except
        return False
    data = data.splitlines()
    reader = csv.reader(data)
    for row in reader:
        if len(row) != 3:
            return False
        recipient, message, amount = row
        if not validate_recipient(recipient):
            return False
        try:
            amount = decimal.Decimal(amount)
        except ValueError:
            return False
        if amount <= 0:
            return False
        rows.append((recipient, message, amount))
    return rows

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
            g.users = [(user.id, user.email) for user in query]
        for user_id, user_email in g.users:
            yield user_id, user_email

def get_categories():
    # prevent database access when app is not yet ready
    if has_app_context():
        if not hasattr(g, 'categories'):
            query = Category.query.order_by(Category.name)
            g.categories = [(category.id, category.name) for category in query]
        for category_id, category_email in g.categories:
            yield category_id, category_email

def get_statuses():
    # prevent database access when app is not yet ready
    if has_app_context():
        if not hasattr(g, 'statuses'):
            query = Proposal.query.distinct(Proposal.status)
            g.statuses = [(proposal.status, proposal.status) for proposal in query]
        for proposal_status_a, proposal_status_b in g.statuses:
            yield proposal_status_a, proposal_status_b

class FilterByProposer(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(Proposal.proposer_id == value)

    def operation(self):
        return u'equals'

    def get_options(self, view):
        # return a generator that is reloaded each time it is used
        return ReloadingIterator(get_users)

class FilterByAuthorizer(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(Proposal.authorizer_id == value)

    def operation(self):
        return u'equals'

    def get_options(self, view):
        # return a generator that is reloaded each time it is used
        return ReloadingIterator(get_users)

class FilterByCategory(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.join(Proposal.categories).filter(Category.id == value)

    def operation(self):
        return u'equals'

    def get_options(self, view):
        # return a generator that is reloaded each time it is used
        return ReloadingIterator(get_categories)

class FilterByStatusEqual(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(Proposal.status == value)

    def operation(self):
        return u'equals'

    def get_options(self, view):
        # return a generator that is reloaded each time it is used
        return ReloadingIterator(get_statuses)

class FilterByStatusNotEqual(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(Proposal.status != value)

    def operation(self):
        return u'not equals'

    def get_options(self, view):
        # return a generator that is reloaded each time it is used
        return ReloadingIterator(get_statuses)

class ProposalModelView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True

    def _format_proposer_column(view, context, model, name):
        if name == 'proposer':
            if not model.proposer:
                return ''
            email = model.proposer.email
        elif name == 'authorizer':
            if not model.authorizer:
                return ''
            email = model.authorizer.email
        else:
            raise Exception('invalid column')
        name = email.split("@")[0]
        html = '<span title="{email}">{name}</span>'.format(email=email, name=name)
        return Markup(html)

    def _format_status_column(view, context, model, name):
        if model.status in (model.STATE_AUTHORIZED, model.STATE_DECLINED, model.STATE_EXPIRED):
            return model.status
        if current_user.has_role(Role.ROLE_ADMIN) or current_user.has_role(Role.ROLE_AUTHORIZER):
            authorize_url = url_for('.authorize_view')
            decline_url = url_for('.decline_view')
            html = '''
                <form action="{authorize_url}" method="POST">
                    <input id="proposal_id" name="proposal_id"  type="hidden" value="{proposal_id}">
                    <button type='submit'>Authorise</button>
                </form>
                <form action="{decline_url}" method="POST">
                    <input id="proposal_id" name="proposal_id"  type="hidden" value="{proposal_id}">
                    <button type='submit'>Decline</button>
                </form>
            '''.format(authorize_url=authorize_url, decline_url=decline_url, proposal_id=model.id)
            return Markup(html)
        return model.status

    def _format_claimed(view, model):
        if model.status == model.STATE_DECLINED:
            return '-'
        total_claimed = 0
        for payment in model.payments:
            if payment.status == payment.STATE_SENT_FUNDS:
                total_claimed += payment.amount
        total_claimed = decimal.Decimal(total_claimed) / 100
        return total_claimed

    def _format_claimed_column(view, context, model, name):
        total_claimed = view._format_claimed(model)
        payments_url = url_for('.payments_view', proposal_id=model.id)

        html = '''
            <a href="{payments_url}">{total_claimed}</a>
        '''.format(payments_url=payments_url, total_claimed=total_claimed)
        return Markup(html)

    def _format_total_column(view, context, model, name):
        if model.status == model.STATE_DECLINED:
            return Markup('-')
        total = 0
        for payment in model.payments:
            total += payment.amount
        total = total / 100
        return Markup(total)

    def _format_totalclaimed_column_export(view, context, model, name):
        total_claimed = view._format_claimed(model)
        return Markup(total_claimed)

    column_default_sort = ('id', True)
    column_list = ('id', 'date', 'proposer', 'categories', 'authorizer', 'reason', 'date_authorized', 'date_expiry', 'status', 'Proposed Total', 'Claimed')
    column_labels = {'proposer': 'Proposed by', 'authorizer': 'Authorized by'}
    column_type_formatters = MY_DEFAULT_FORMATTERS
    column_formatters = {'proposer': _format_proposer_column, 'authorizer': _format_proposer_column, 'status': _format_status_column, 'Proposed Total': _format_total_column, 'Claimed': _format_claimed_column}
    column_filters = [ DateBetweenFilter(Proposal.date, 'Search Date'), DateTimeGreaterFilter(Proposal.date, 'Search Date'), DateSmallerFilter(Proposal.date, 'Search Date'), FilterByStatusEqual(None, 'Search Status'), FilterByStatusNotEqual(None, 'Search Status'), FilterByProposer(None, 'Search Proposer'), FilterByAuthorizer(None, 'Search Authorizer'), FilterByCategory(None, 'Search Category') ]
    column_export_list = ('id', 'date', 'proposer', 'categories', 'authorizer', 'reason', 'date_authorized', 'date_expiry', 'status', 'total', 'claimed')
    column_formatters_export = {'total': _format_total_column, 'claimed': _format_totalclaimed_column_export}
    form_columns = ['reason', 'categories', 'recipient', 'message', 'amount', 'csvfile']
    form_extra_fields = {'recipient': TextField('Recipient'), 'message': TextField('Message'), 'amount': DecimalField('Amount', validators=[validators.Optional()]), 'csvfile': FileField('CSV File')}

    def _validate_form(self, form):
        csv_rows = None
        if not form.reason.data:
            return False, "Empty reason value", csv_rows
        # do csv file first
        if form.csvfile.data:
            csv_rows = validate_csv(form.csvfile.data.stream.read())
            if not csv_rows:
                return False, "Invalid CSV file", csv_rows
        else:
            # if not csv file then do other:
            if not validate_recipient(form.recipient.data):
                return False, "Recipient is invalid", csv_rows
            if not form.amount.data or form.amount.data <= 0:
                return False, "Amount must be greater then 0", csv_rows
        return True, "", csv_rows

    def _add_payment(self, model, recipient, message, amount):
        email = recipient if is_email(recipient) else None
        mobile = recipient if is_mobile(recipient) else None
        address = recipient if is_address(recipient) else None
        amount = int(amount * 100)
        payment = Payment(model, mobile, email, address, message, amount)
        self.session.add(payment)

    def on_model_change(self, form, model, is_created):
        if is_created:
            # validate
            res, msg, csv_rows = self._validate_form(form)
            if not res:
                raise validators.ValidationError(msg)
            # generate model defaults
            model.generate_defaults()
            # set proposer
            model.proposer = current_user
            # check csv file first
            if form.csvfile.data:
                for recipient, message, amount in csv_rows:
                    self._add_payment(model, recipient, message, amount)
            # or just process basic fields
            else:
                recipient = form.recipient.data
                message = form.message.data
                amount = form.amount.data
                self._add_payment(model, recipient, message, amount)

    def is_accessible(self):
        if not (current_user.is_active and current_user.is_authenticated):
            return False
        if current_user.has_role(Role.ROLE_ADMIN):
            self.can_create = True
            return True
        if current_user.has_role(Role.ROLE_PROPOSER):
            self.can_create = True
            return True
        return False

    @expose('authorize', methods=['POST'])
    def authorize_view(self):
        return_url = self.get_url('.index_view')
        # check permission
        if not (current_user.has_role(Role.ROLE_ADMIN) or current_user.has_role(Role.ROLE_AUTHORIZER)):
            # permission denied
            flash('Not authorized.', 'error')
            return redirect(return_url)
        # get the model from the database
        form = get_form_data()
        if not form:
            flash('Could not get form data.', 'error')
            return redirect(return_url)
        proposal_id = form['proposal_id']
        proposal = self.get_one(proposal_id)
        if proposal is None:
            flash('Proposal not not found.', 'error')
            return redirect(return_url)
        # process the proposal
        proposal.authorize(current_user)
        # commit to db
        try:
            self.session.commit()
            flash('Proposal {proposal_id} set as authorized'.format(proposal_id=proposal_id))
        except (SQLAlchemyError, DBAPIError) as ex:
            if not self.handle_view_exception(ex):
                raise
            flash('Failed to set proposal {proposal_id} as authorized'.format(proposal_id=proposal_id), 'error')
        return redirect(return_url)

    @expose('decline', methods=['POST'])
    def decline_view(self):
        return_url = self.get_url('.index_view')
        # check permission
        if not (current_user.has_role(Role.ROLE_ADMIN) or current_user.has_role(Role.ROLE_AUTHORIZER)):
            # permission denied
            flash('Not authorized.', 'error')
            return redirect(return_url)
        # get the model from the database
        form = get_form_data()
        if not form:
            flash('Could not get form data.', 'error')
            return redirect(return_url)
        proposal_id = form['proposal_id']
        proposal = self.get_one(proposal_id)
        if proposal is None:
            flash('Proposal not not found.', 'error')
            return redirect(return_url)
        # process the proposal
        if proposal.status == proposal.STATE_CREATED:
            proposal.status = proposal.STATE_DECLINED
            proposal.authorizer = current_user
        # commit to db
        try:
            self.session.commit()
            flash('Proposal {proposal_id} set as declined'.format(proposal_id=proposal_id))
        except (SQLAlchemyError, DBAPIError) as ex:
            if not self.handle_view_exception(ex):
                raise
            flash('Failed to set proposal {proposal_id} as declined'.format(proposal_id=proposal_id), 'error')
        return redirect(return_url)

    @expose('payments/<proposal_id>', methods=['GET'])
    def payments_view(self, proposal_id):
        return_url = self.get_url('.index_view')
        # check permission
        if not (current_user.has_role(Role.ROLE_ADMIN) or current_user.has_role(Role.ROLE_AUTHORIZER) or current_user.has_role(Role.ROLE_PROPOSER)):
            # permission denied
            flash('Not authorized.', 'error')
            return redirect(return_url)
        # get the model from the database
        proposal = self.get_one(proposal_id)
        if proposal is None:
            flash('Proposal not not found.', 'error')
            return redirect(return_url)
        # show the proposal payments
        return self.render('admin/payments.html', payments=proposal.payments)

class UserModelView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False
    column_list = ['token', 'email', 'roles', 'active', 'confirmed_at']
    column_editable_list = ['roles', 'active']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role(Role.ROLE_ADMIN))

class TopicModelView(RestrictedModelView):
    can_create = True
    can_delete = True
    can_edit = False

class WavesTxModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False

    def _format_date(view, context, model, name):
        if model.date:
            return datetime.datetime.fromtimestamp(model.date).strftime('%Y-%m-%d %H:%M:%S')
        return None

    def _format_json_data_html_link(view, context, model, name):
        ids = model.id
        json_obj = json.loads(model.json_data)
        asset_id = json_obj["assetId"]
        fee_asset_id = json_obj["feeAssetId"]
        sender_public_key = json_obj["senderPublicKey"]
        recipient = json_obj["recipient"]
        amount = json_obj["amount"]/100
        fee = json_obj["fee"]/100
        timestamp = json_obj["timestamp"]
        attachment = json_obj["attachment"]
        signature = json_obj["signature"]
        txtype = json_obj["type"]

        # pylint: disable=duplicate-string-formatting-argument
        html = '''
        <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#TxDetailsModal{}">
        Tx Details
        </button>

<div class="modal fade" id="TxDetailsModal{}" tabindex="-1" role="dialog" aria-labelledby="TxDetailsModalLabel{}" aria-hidden="true">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h4 class="modal-title" id="TxDetailModalLabel{}">Transaction Details</h4>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">
         assetId: {}<br/>
         feeAssetId: {}<br/>
         senderPublicKey: {}<br/>
         recipient: {}<br/>
         amount: {} {}<br/> 
         fee: {}</br>
         timestamp: {}<br/>
         attachment: {}<br/>
         signature: {}<br/>
         type: {}<br/>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
        '''.format(ids, ids, ids, ids, asset_id, fee_asset_id, sender_public_key, recipient, amount, app.config["ASSET_NAME"], fee, timestamp, attachment, signature, txtype)
        return Markup(html)

    def _format_txid_html(view, context, model, name):
        ids = model.txid
        truncate_txids = str(ids[:6]+'...')
        # pylint: disable=duplicate-string-formatting-argument
        html = '''
        <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#TxidModal{}">
        {}
        </button>
<div class="modal fade" id="TxidModal{}" tabindex="-1" role="dialog" aria-labelledby="TxidModalLabel{}" aria-hidden="true">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="TxidModalLabel{}">Transaction ID</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">
         {}
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
        '''.format(ids, truncate_txids, ids, ids, ids, ids)
        return Markup(html)

    column_list = ['date', 'txid', 'type', 'state', 'amount', 'json_data_signed', 'json_data']
    column_formatters = {'date': _format_date, 'txid':_format_txid_html, 'json_data': _format_json_data_html_link}

### define token distribution models

class WavesTxSchema(Schema):
    date = fields.Date()
    txid = fields.String()
    type = fields.String()
    state = fields.String()
    amount = fields.Integer()
    json_data_signed = fields.Boolean()
    json_data = fields.String()

class WavesTx(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Integer, nullable=False)
    txid = db.Column(db.String, nullable=False, unique=True)
    type = db.Column(db.String, nullable=False)
    state = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    json_data_signed = db.Column(db.Boolean, nullable=False)
    json_data = db.Column(db.String, nullable=False)

    def __init__(self, txid, type_, state, amount, json_data_signed, json_data):
        self.date = time.time()
        self.type = type_
        self.state = state
        self.txid = txid
        self.amount = amount
        self.json_data_signed = json_data_signed
        self.json_data = json_data

    @classmethod
    def from_txid(cls, session, txid):
        return session.query(cls).filter(cls.txid == txid).first()

    @classmethod
    def expire_transactions(cls, session, above_age, from_state, to_state):
        now = time.time()
        txs = session.query(cls).filter(cls.date < now - above_age, cls.state == from_state).all()
        for tx in txs:
            tx.state = to_state
            tx.json_data = ""
            session.add(tx)
        return len(txs)

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    def __repr__(self):
        return '<WavesTx %r>' % (self.txid)

    def to_json(self):
        tx_schema = WavesTxSchema()
        return tx_schema.dump(self).data

    def tx_with_sigs(self):
        tx = json.loads(self.json_data)
        if self.json_data_signed:
            return tx
        proofs = tx["proofs"]
        for sig in self.signatures:
            while sig.signer_index >= len(proofs):
                proofs.append('todo')
            proofs[sig.signer_index] = sig.value
        return tx

class WavesTxSig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    waves_tx_id = db.Column(db.Integer, db.ForeignKey('waves_tx.id'), nullable=False)
    waves_tx = db.relationship('WavesTx', backref=db.backref('signatures', lazy='dynamic'))
    signer_index = db.Column(db.Integer, nullable=False)
    value = db.Column(db.String, unique=False)

    def __init__(self, waves_tx, signer_index, value):
        self.waves_tx = waves_tx
        self.signer_index = signer_index
        self.value = value

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

class PayDbUserTransactionsView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated)

    def get_query(self):
        return self.session.query(self.model).filter(or_(self.model.sender_token == current_user.token, self.model.recipient_token == current_user.token))

    def get_count_query(self):
        return self.session.query(db.func.count('*')).filter(or_(self.model.sender_token == current_user.token, self.model.recipient_token == current_user.token)) # pylint: disable=no-member

class UserStash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String)
    email_hash = db.Column(db.String, nullable=False, unique=True)
    iv = db.Column(db.String)
    cyphertext = db.Column(db.String)
    question = db.Column(db.String)

    def __init__(self, stash_request):
        self.key = stash_request.key
        self.email_hash = stash_request.email_hash
        self.iv = stash_request.iv # pylint: disable=invalid-name
        self.cyphertext = stash_request.cyphertext
        self.question = stash_request.question

    @classmethod
    def from_email_hash(cls, session, key, email_hash):
        return session.query(cls).filter(and_(cls.key == key, cls.email_hash == email_hash)).first()

class UserStashRequest(db.Model):
    MINUTES_EXPIRY = 30
    ACTION_SAVE = 'save'
    ACTION_LOAD = 'load'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String)
    email_hash = db.Column(db.String, nullable=False)
    iv = db.Column(db.String)
    cyphertext = db.Column(db.String)
    question = db.Column(db.String)

    action = db.Column(db.String)
    token = db.Column(db.String, unique=True)
    secret = db.Column(db.String)
    expiry = db.Column(db.DateTime())

    created_stash_id = db.Column(db.Integer, db.ForeignKey('user_stash.id'))
    created_stash = db.relationship('UserStash', foreign_keys=[created_stash_id])
    loaded_stash_id = db.Column(db.Integer, db.ForeignKey('user_stash.id'))
    loaded_stash = db.relationship('UserStash', foreign_keys=[loaded_stash_id])

    def __init__(self, key, email, iv, cyphertext, question, action):
        self.key = key
        self.email_hash = sha256(email)
        self.iv = iv # pylint: disable=invalid-name
        self.cyphertext = cyphertext
        self.question = question
        self.action = action
        self.token = secrets.token_urlsafe(8)
        self.secret = secrets.token_urlsafe(16)
        self.expiry = datetime.datetime.now() + datetime.timedelta(self.MINUTES_EXPIRY)

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

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
        self.token = secrets.token_urlsafe(8)
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
        return ref_schema.dump(self).data

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def from_token_user(cls, session, token, user):
        return session.query(cls).filter(and_(cls.token == token, cls.user_id == user.id)).first()

    @classmethod
    def from_user(cls, session, user):
        return session.query(cls).filter(cls.user_id == user.id).all()
