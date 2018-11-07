import time

from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey
import sqlalchemy.types as types
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func
from sqlalchemy import or_, and_, desc
from marshmallow import Schema, fields

from database import Base
import config

cfg = config.read_cfg()

class TransactionSchema(Schema):
    txid = fields.String()
    sender = fields.String()
    recipient = fields.String()
    amount = fields.Integer()
    attachment = fields.String()
    invoice_id = fields.String()
    block_num = fields.Integer()
    block_date = fields.Integer()

class Transaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True)
    txid = Column(String, nullable=False, unique=True)
    sender = Column(String, nullable=False)
    recipient = Column(String, nullable=False)
    amount = Column(Integer, nullable=False)
    attachment = Column(String, nullable=True)
    invoice_id = Column(String, nullable=True)
    block_id = Column(Integer, ForeignKey('blocks.id'))
    block = relationship('Block')

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

class Block(Base):
    __tablename__ = 'blocks'
    id = Column(Integer, primary_key=True)
    date = Column(Float, nullable=False, unique=False)
    num = Column(Integer, nullable=False)
    hash = Column(String, nullable=False, unique=True)
    reorged = Column(Boolean, nullable=False, default=False)
    transactions = relationship('Transaction')

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

class CreatedTransaction(Base):
    __tablename__ = 'created_transactions'
    id = Column(Integer, primary_key=True)
    date = Column(Integer, nullable=False)
    txid = Column(String, nullable=False, unique=True)
    state = Column(String, nullable=False)
    amount = Column(Integer, nullable=False)
    json_data = Column(String, nullable=False)

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

class Setting(Base):
    __tablename__ = 'settings'
    id = Column(Integer, primary_key=True)
    key = Column(String, nullable=False, unique=True)
    value = Column(String, unique=False)

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return '<Setting %r %r>' % (self.key, self.value)

class DashboardHistory(Base):
    __tablename__ = "dashboard_history"
    id = Column(Integer, primary_key=True)
    date = Column(Integer, nullable=False)
    incomming_tx_count = Column(Integer, nullable=False)
    created_tx_count = Column(Integer, nullable=False)
    zap_balance = Column(Integer, nullable=False)
    master_waves_balance = Column(Integer, nullable=False)

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
