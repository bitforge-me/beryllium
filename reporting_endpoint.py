# pylint: disable=unbalanced-tuple-unpacking
# pylint: disable=too-many-locals

import logging
import datetime
from datetime import date, timedelta
from dateutil.relativedelta import relativedelta
from sqlalchemy import func, and_

from flask import Blueprint, render_template, redirect, Response
from flask_security import roles_accepted

from app_core import db
from models import Role, User, BrokerOrder
import utils
import dasset

logger = logging.getLogger(__name__)
reporting = Blueprint('reporting', __name__, template_folder='templates/reporting')

### FREQUECNY DATES USED
TODAY = date.today()
YESTERDAY = TODAY - timedelta(days=1)
TOMORROW = TODAY + timedelta(days=1)
WEEKDAY = TODAY.weekday()
MONDAY = TODAY - timedelta(days=WEEKDAY)
SUNDAY = TODAY + timedelta(days=(6 - WEEKDAY))
NEXT_MONDAY = TODAY + datetime.timedelta(days=-TODAY.weekday(), weeks=1)
FIRST_DAY_CURRENT_MONTH = TODAY.replace(day=1)
FIRST_DAY_NEXT_MONTH = FIRST_DAY_CURRENT_MONTH + relativedelta(months=+1)
LAST_DAY_NEXT_MONTH = FIRST_DAY_NEXT_MONTH - timedelta(days=1)
FIRST_DAY_CURRENT_YEAR = FIRST_DAY_CURRENT_MONTH + relativedelta(month=1)
FIRST_DAY_NEXT_YEAR = FIRST_DAY_CURRENT_YEAR + relativedelta(years=+1)
LAST_DAY_CURRENT_YEAR = FIRST_DAY_NEXT_YEAR - timedelta(days=1)

def report_dashboard_general(dasset_balances):
    ### General Info
    return render_template('reporting/dashboard_general.html', dasset_balances=dasset_balances)

def report_dashboard_broker_order():
    orders_data = {}
    for market in dasset.MARKETS:
        asset_symbol = market.split('-')[0]
        order_count_today = broker_order_count(BrokerOrder, TODAY, TOMORROW, market)
        order_count_yesterday = broker_order_count(BrokerOrder, YESTERDAY, TODAY, market)
        order_count_week = broker_order_count(BrokerOrder, MONDAY, NEXT_MONDAY, market)
        order_count_month = broker_order_count(BrokerOrder, FIRST_DAY_CURRENT_MONTH, FIRST_DAY_NEXT_MONTH, market)
        order_count_year = broker_order_count(BrokerOrder, FIRST_DAY_CURRENT_YEAR, FIRST_DAY_NEXT_YEAR, market)
        order_count_lifetime = broker_order_count_lifetime(BrokerOrder, market)
        order_amount_today = broker_order_amount(BrokerOrder, TODAY, TOMORROW, market)
        order_amount_yesterday = broker_order_amount(BrokerOrder, YESTERDAY, TODAY, market)
        order_amount_week = broker_order_amount(BrokerOrder, MONDAY, NEXT_MONDAY, market)
        order_amount_month = broker_order_amount(BrokerOrder, FIRST_DAY_CURRENT_MONTH, FIRST_DAY_NEXT_MONTH, market)
        order_amount_year = broker_order_amount(BrokerOrder, FIRST_DAY_CURRENT_YEAR, FIRST_DAY_NEXT_YEAR, market)
        order_amount_lifetime = broker_order_amount_lifetime(BrokerOrder, market)
        orders_data[market] = dict(asset_symbol=asset_symbol, order_count_today=order_count_today, order_count_yesterday=order_count_yesterday, order_count_week=order_count_week, order_count_month=order_count_month, order_count_year=order_count_year, order_count_lifetime=order_count_lifetime, order_amount_today=order_amount_today, order_amount_yesterday=order_amount_yesterday, order_amount_week=order_amount_week, order_amount_month=order_amount_month, order_amount_year=order_amount_year, order_amount_lifetime=order_amount_lifetime)
    return render_template('reporting/dashboard_broker_orders.html', orders_data=orders_data)

def report_user_balance():
    ### User queries
    users = User.query.all()
    user_count = User.query.count()
    user_count_today = user_counting(User, TODAY, TOMORROW)
    user_count_yesterday = user_counting(User, YESTERDAY, TODAY)
    user_count_weekly = user_counting(User, MONDAY, NEXT_MONDAY)
    user_count_monthly = user_counting(User, FIRST_DAY_CURRENT_MONTH, FIRST_DAY_NEXT_MONTH)
    user_count_yearly = user_counting(User, FIRST_DAY_CURRENT_YEAR, FIRST_DAY_NEXT_YEAR)
    users_balances = []
    for account_user in users:
        user = User.from_email(db.session, account_user.email)
        if user:
            balance = 0
            balance = utils.int2asset(balance)
            email_balance = {'user': user.email, 'balance': balance}
            users_balances.append(email_balance)
            sorted_users_balances = sorted(users_balances, key=lambda k:float(k['balance']), reverse=True)
    return render_template("reporting/dashboard_user_balance.html", user_count=user_count, users_balances=sorted_users_balances[:10], user_count_today=user_count_today, user_count_yesterday=user_count_yesterday, user_count_weekly=user_count_weekly, user_count_monthly=user_count_monthly, user_count_yearly=user_count_yearly, user_count_lifetime=user_count)

def user_counting(table, start_date, end_date):
    result = table.query.filter(and_(table.confirmed_at >= str(start_date), table.confirmed_at <= str(end_date))).count()
    if not result:
        result = 0
    return result

def transaction_count(table, start_date, end_date):
    result = table.query.filter(and_(table.date >= str(start_date), table.date < str(end_date))).count()
    if not result:
        result = 0
    return result

def asset_amount_format(data, market):
    if market == 'BTC-NZD':
        format_data = data / 100000000
    elif market == 'ETH-NZD':
        format_data = data / 1000000000000000000
    else:
        format_data = data / 100000000
    return format_data

def broker_order_amount(table, start_date, end_date, market):
    result = table.query.filter(table.market == market)\
            .filter(and_(table.date >= str(start_date), table.date < str(end_date)))\
            .with_entities(func.sum(table.base_amount)).scalar()
    if not result:
        result = 0
    result = '{0:.4f}'.format(asset_amount_format(result, market))
    return result

def broker_order_amount_lifetime(table, market):
    result = table.query.filter(table.market == market)\
            .with_entities(func.sum(table.base_amount)).scalar()
    if not result:
        result = 0
    result = '{0:.4f}'.format(asset_amount_format(result, market))
    return result

def broker_order_count(table, start_date, end_date, market):
    result = table.query.filter(table.market == market)\
            .filter(and_(table.date >= str(start_date), table.date < str(end_date)))\
            .count()
    if not result:
        result = 0
    return result

def broker_order_count_lifetime(table, market):
    result = table.query.filter(table.market == market)\
            .count()
    if not result:
        result = 0
    return result

def from_int_to_user_friendly(val, divisor, decimal_places=4):
    if not isinstance(val, int):
        return val
    val = val / divisor
    return round(val, decimal_places)

def dashboard_data_general():
    dasset_balances = dasset.balances_req()
    return {"dasset_balances": dasset_balances}

@reporting.route("/dashboard")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard():
    return redirect('dashboard_general')

@reporting.route("/dashboard_general")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_general():
    data = dashboard_data_general()
    return report_dashboard_general(data["dasset_balances"]) 

@reporting.route("/dashboard_report_broker_order")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_report_broker_order():
    return report_dashboard_broker_order()

### List username with their balances
@reporting.route("/dashboard_user_balance")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_user_balance():
    return report_user_balance()

@reporting.route("/download_user_balance")
def download_user_balance():
    users = User.query.all()
    users_balances = []
    for account_user in users:
        user = User.from_email(db.session, account_user.email)
        if user:
            balance = 0
            balance = utils.int2asset(balance)
            email_balance = {'user': user.email, 'balance': balance}
            users_balances.append(email_balance)
    sorted_users_balances = sorted(users_balances, key=lambda k:float(k['balance']), reverse=True)
    csv = []
    csv.append(str('User')+','+str('Balance')+'\n')
    for user_balance in sorted_users_balances:
        csv.append(str(user_balance['user'])+','+str(user_balance['balance'])+'\n')
    return Response(
        csv,
        mimetype="text/csv",
        headers={"Content-disposition":
                 "attachment; filename=user_balance.csv"})
