import time
import datetime
import decimal
import csv
import logging
import json

from flask import redirect, url_for, request, flash, has_app_context, g
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
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
from sqlalchemy import func
import requests

from app_core import app, db
from utils import generate_key, is_email, is_mobile, is_address

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
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    @classmethod
    def from_name(cls, session, name):
        return session.query(cls).filter(cls.name == name).first()

    def __str__(self):
        return self.name

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    def __str__(self):
        return self.email

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
    wallet_address = db.Column(db.String(255))
    message = db.Column(db.String())
    amount = db.Column(db.Integer)
    status = db.Column(db.String(255))
    txid = db.Column(db.String(255))

    def __init__(self, proposal, mobile, email, wallet_address, message, amount):
        self.proposal = proposal
        self.token = generate_key(8)
        self.mobile = mobile
        self.email = email
        self.wallet_address = wallet_address
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
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    @classmethod
    def from_name(cls, session, name):
        return session.query(cls).filter(cls.name == name).first()

    def __str__(self):
        return self.name

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
        self.proposer = current_user
        self.authorizer = None
        self.date_authorized = None
        self.date_expiry = None
        self.status = self.STATE_CREATED

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
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

class RestrictedModelView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False
    column_exclude_list = ['password', 'secret']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('admin'))

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
    except:
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
        for proposal_status, proposal_status in g.statuses:
            yield proposal_status, proposal_status

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
        if current_user.has_role('admin') or current_user.has_role('authorizer'):
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
        if current_user.has_role('admin'):
            self.can_create = True
            return True
        if current_user.has_role('proposer'):
            self.can_create = True
            return True
        return False

    @expose('authorize', methods=['POST'])
    def authorize_view(self):
        return_url = self.get_url('.index_view')
        # check permission
        if not (current_user.has_role('admin') or current_user.has_role('authorizer')):
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
            proposal.status = proposal.STATE_AUTHORIZED
            now = datetime.datetime.now()
            proposal.date_authorized = now
            proposal.date_expiry = now + datetime.timedelta(hours = Proposal.HOURS_EXPIRY)
            proposal.authorizer = current_user
        # commit to db
        try:
            self.session.commit()
            flash('Proposal {proposal_id} set as authorized'.format(proposal_id=proposal_id))
        except Exception as ex:
            if not self.handle_view_exception(ex):
                raise
            flash('Failed to set proposal {proposal_id} as authorized'.format(proposal_id=proposal_id), 'error')
        return redirect(return_url)

    @expose('decline', methods=['POST'])
    def decline_view(self):
        return_url = self.get_url('.index_view')
        # check permission
        if not (current_user.has_role('admin') or current_user.has_role('authorizer')):
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
        except Exception as ex:
            if not self.handle_view_exception(ex):
                raise
            flash('Failed to set proposal {proposal_id} as declined'.format(proposal_id=proposal_id), 'error')
        return redirect(return_url)

    @expose('payments/<proposal_id>', methods=['GET'])
    def payments_view(self, proposal_id):
        return_url = self.get_url('.index_view')
        # check permission
        if not (current_user.has_role('admin') or current_user.has_role('authorizer') or current_user.has_role('proposer')):
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
    column_list = ['email', 'roles']
    column_editable_list = ['roles']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('admin'))

class TopicModelView(RestrictedModelView):
    can_create = True
    can_delete = True
    can_edit = False

### define token distribution models

class TokenTxSchema(Schema):
    date = fields.Date()
    txid = fields.String()
    type = fields.String()
    state = fields.String()
    amount = fields.Integer()
    json_data_signed = fields.Boolean()
    json_data = fields.String()

class TokenTx(db.Model):
    __tablename__ = 'token_txs'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Integer, nullable=False)
    txid = db.Column(db.String, nullable=False, unique=True)
    type = db.Column(db.String, nullable=False)
    state = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    json_data_signed = db.Column(db.Boolean, nullable=False)
    json_data = db.Column(db.String, nullable=False)

    def __init__(self, txid, type, state, amount, json_data_signed, json_data):
        self.date = time.time()
        self.type = type
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
        return '<TokenTx %r>' % (self.txid)

    def to_json(self):
        tx_schema = TokenTxSchema()
        return tx_schema.dump(self).data

    def tx_with_sigs(self):
        tx = json.loads(self.json_data)
        if self.json_data_signed:
            return tx
        proofs = tx["proofs"]
        for sig in self.signatures:
            while sig.signer_index >= len(proofs):
                proofs.append('todo')
            proofs[signer_index] = sig.value
        return tx

class TxSig(db.Model):
    __tablename__ = 'tx_sigs'
    id = db.Column(db.Integer, primary_key=True)
    token_tx_id = db.Column(db.Integer, db.ForeignKey('token_txs.id'), nullable=False)
    token_tx = db.relationship('TokenTx', backref=db.backref('signatures', lazy='dynamic'))
    signer_index = db.Column(db.Integer, nullable=False)
    value = db.Column(db.String, unique=False)

    def __init__(self, token_tx, signer_index, value):
        self.token_tx = token_tx
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
