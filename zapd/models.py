import time

from flask import redirect, url_for, request
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_admin.contrib import sqla
from marshmallow import Schema, fields

from app_core import app, db

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
                current_user.has_role('admin')
        )

class UserModelView(BaseModelView):
    can_create = True
    can_delete = True
    can_edit = False
    column_exclude_list = ['password']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated
        )

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
