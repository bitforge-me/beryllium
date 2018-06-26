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
    from_ = fields.String()
    to = fields.String()
    value = fields.String()
    attachment = fields.String()
    invoice_id = fields.String()
    block_num = fields.Integer()

class Transaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True)
    txid = Column(String, nullable=False, unique=True)
    from_ = Column(String, nullable=False)
    to = Column(String, nullable=False)
    value = Column(Integer, nullable=False)
    attachment = Column(String, nullable=True)
    invoice_id = Column(String, nullable=True)
    block_num = Column(Integer, nullable=False)

    def __init__(self, txid, from_, to, value, attachment, invoice_id, block_num):
        self.txid = txid
        self.from_ = from_
        self.to = to
        self.value = value
        self.attachment = attachment
        self.invoice_id = invoice_id
        self.block_num = block_num

    @classmethod
    def from_txid(cls, session, txid):
        return session.query(cls).filter(cls.txid == txid).first()

    @classmethod
    def from_invoice_id(cls, session, invoice_id):
        return session.query(cls).filter(cls.invoice_id == invoice_id).all()

    def __repr__(self):
        return '<Transaction %r>' % (self.txid)

    def to_json(self):
        tx_schema = TransactionSchema()
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
