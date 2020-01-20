import time
import datetime
import decimal
import csv

from flask import redirect, url_for, request, flash
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_admin import expose
from flask_admin.babel import lazy_gettext
from flask_admin.helpers import get_form_data
from flask_admin.contrib import sqla
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from flask_admin.model import filters
from wtforms.fields import TextField, DecimalField, FileField
from wtforms import validators
from marshmallow import Schema, fields
from markupsafe import Markup

from app_core import app, db
from utils import generate_key, is_email, is_mobile, is_address

### Define zapsend models

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
        self.token = generate_key()
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

class ProposalModelView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True

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

    def _format_total_column(view, context, model, name):
        if model.status == model.STATE_DECLINED:
            return Markup('-')
        total = 0
        total_claimed = 0
        for payment in model.payments:
            total += payment.amount
            if payment.status == payment.STATE_SENT_FUNDS:
                total_claimed += payment.amount
        total = decimal.Decimal(total) / 100
        total_claimed = decimal.Decimal(total_claimed) / 100
        payments_url = url_for('.payments_view', proposal_id=model.id)
        if total_claimed == total:
            html = '''
                <a href="{payments_url}">{total}</a>
            '''.format(payments_url=payments_url, total=total)
        else:
            html = '''
                <a href="{payments_url}">{total} ({total_claimed})</a>
            '''.format(payments_url=payments_url, total=total, total_claimed=total_claimed)
        return Markup(html)

    column_default_sort = ('id', True)
    column_list = ('id', 'date', 'proposer', 'categories', 'authorizer', 'reason', 'date_authorized', 'date_expiry', 'status', 'total')
    column_labels = {'proposer': 'Proposed by', 'authorizer': 'Authorized by'}
    column_formatters = {'status': _format_status_column, 'total': _format_total_column}
    column_filters = [ DateBetweenFilter(Proposal.date, 'Search Date'), DateTimeGreaterFilter(Proposal.date, 'Search Date'), DateSmallerFilter(Proposal.date, 'Search Date'), FilterEqual(Proposal.status, 'Search Status'), FilterNotEqual(Proposal.status, 'Search Status') ]
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
            proposal.date_expiry = now + datetime.timedelta(days = 3)
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

### define payment processing models

class TransactionSchema(Schema):
    txid = fields.String()
    sender = fields.String()
    recipient = fields.String()
    amount = fields.Integer()
    attachment = fields.String()
    invoice_id = fields.String()
    block_num = fields.Integer()
    block_date = fields.Integer()

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    txid = db.Column(db.String, nullable=False, unique=True)
    sender = db.Column(db.String, nullable=False)
    recipient = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    attachment = db.Column(db.String, nullable=True)
    invoice_id = db.Column(db.String, nullable=True)
    block_id = db.Column(db.Integer, db.ForeignKey('blocks.id'))
    block = db.relationship('Block')

    def __init__(self, txid, sender, recipient, amount, attachment, invoice_id, block_id):
        self.txid = txid
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.attachment = attachment
        self.invoice_id = invoice_id
        self.block_id = block_id

    @classmethod
    def from_txid(cls, session, txid):
        return session.query(cls).filter(cls.txid == txid).first()

    @classmethod
    def from_invoice_id(cls, session, invoice_id, start_date, end_date, offset, limit):
        query = session.query(cls)
        if invoice_id:
            query = query.filter(cls.invoice_id == invoice_id)
        if start_date != 0 or end_date != 0:
            query = query.join(Block)
            if start_date != 0:
                query = query.filter(Block.date >= start_date)
            if end_date != 0:
                query = query.filter(Block.date <= end_date)
        query = query.offset(offset).limit(limit)
        return query.all()

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    def __repr__(self):
        return '<Transaction %r>' % (self.txid)

    def to_json(self):
        self.block_num = self.block.num
        self.block_date = self.block.date
        tx_schema = TransactionSchema()
        return tx_schema.dump(self).data

class Block(db.Model):
    __tablename__ = 'blocks'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Float, nullable=False, unique=False)
    num = db.Column(db.Integer, nullable=False)
    hash = db.Column(db.String, nullable=False, unique=True)
    reorged = db.Column(db.Boolean, nullable=False, default=False)
    transactions = db.relationship('Transaction')

    def __init__(self, block_date, block_num, block_hash):
        self.date = block_date
        self.num = block_num
        self.hash = block_hash
        self.reorged = False

    def set_reorged(self, session):
        for tx in self.transactions:
            session.delete(tx)
        self.reorged = True
        session.add(self)

    @classmethod
    def last_block(cls, session):
        return session.query(cls).filter(cls.reorged == False).order_by(cls.id.desc()).first()

    @classmethod
    def from_number(cls, session, num):
        return session.query(cls).filter((cls.num == num) & (cls.reorged == False)).first()

    @classmethod
    def from_hash(cls, session, hash):
        return session.query(cls).filter(cls.hash == hash).first()

    @classmethod
    def tx_block_num(cls, session, tx_block_id):
        if tx_block_id:
            block = session.query(cls).filter(cls.id == tx_block_id).first()
            if block:
                return block.num 
        return -1

    @classmethod
    def tx_confirmations(cls, session, current_block_num, tx_block_id):
        block_num = cls.tx_block_num(session, tx_block_id)
        if block_num != -1:
                return current_block_num - block_num 
        return 0

    def __repr__(self):
        return '<Block %r %r>' % (self.num, self.hash)

class CreatedTransactionSchema(Schema):
    date = fields.Date()
    txid = fields.String()
    state = fields.String()
    amount = fields.Integer()
    json_data = fields.String()

class CreatedTransaction(db.Model):
    __tablename__ = 'created_transactions'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Integer, nullable=False)
    txid = db.Column(db.String, nullable=False, unique=True)
    state = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    json_data = db.Column(db.String, nullable=False)

    def __init__(self, txid, state, amount, json_data):
        self.date = time.time()
        self.state = state
        self.txid = txid
        self.amount = amount
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
        return '<CreatedTransaction %r>' % (self.txid)

    def to_json(self):
        tx_schema = CreatedTransactionSchema()
        return tx_schema.dump(self).data

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

class DashboardHistory(db.Model):
    __tablename__ = "dashboard_history"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Integer, nullable=False)
    incomming_tx_count = db.Column(db.Integer, nullable=False)
    created_tx_count = db.Column(db.Integer, nullable=False)
    zap_balance = db.Column(db.Integer, nullable=False)
    master_waves_balance = db.Column(db.Integer, nullable=False)

    def __init__(self, incomming_tx_count, created_tx_count, zap_balance, master_waves_balance):
        self.date = time.time()
        self.incomming_tx_count = incomming_tx_count
        self.created_tx_count = created_tx_count
        self.zap_balance = zap_balance
        self.master_waves_balance = master_waves_balance

    @classmethod
    def last_entry(cls, session):
        return session.query(cls).order_by(cls.id.desc()).first()

    @classmethod
    def last_week(cls, session):
        now = time.time()
        week = 60 * 60 * 24 * 7
        return session.query(cls).filter(cls.date > now - week).all()
