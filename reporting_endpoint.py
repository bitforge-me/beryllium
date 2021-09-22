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
from models import Role, User
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

def report_dashboard_premio(premio_balance, premio_stage_account, total_balance, claimable, dasset_balances):
    ### Premio (PayDbTransaction)
    premio_tx_count_lifetime = -1 #PayDbTransaction.query.count()
    premio_tx_count_today = -1 #transaction_count(PayDbTransaction, TODAY, TOMORROW)
    premio_tx_count_yesterday = -1 #transaction_count(PayDbTransaction, YESTERDAY, TODAY)
    premio_tx_count_week = -1 #transaction_count(PayDbTransaction, MONDAY, NEXT_MONDAY)
    premio_tx_count_month = -1 #transaction_count(PayDbTransaction, FIRST_DAY_CURRENT_MONTH, FIRST_DAY_NEXT_MONTH)
    premio_tx_count_year = -1 #transaction_count(PayDbTransaction, FIRST_DAY_CURRENT_YEAR, FIRST_DAY_NEXT_YEAR)
    return render_template('reporting/dashboard_paydb_premio.html', premio_balance=premio_balance, premio_stage_account=premio_stage_account, total_balance=total_balance, claimable=claimable, \
        premio_tx_count_lifetime=premio_tx_count_lifetime, \
        premio_tx_count_today=premio_tx_count_today, premio_tx_count_yesterday=premio_tx_count_yesterday, \
        premio_tx_count_week=premio_tx_count_week, premio_tx_count_month=premio_tx_count_month, premio_tx_count_year=premio_tx_count_year, \
        dasset_balances=dasset_balances)

def report_dashboard_proposals():
    ### RewardProposal queries
    proposal_count = -1 #RewardProposal.query.count()
    proposal_count_today = -1 #transaction_count(RewardProposal, TODAY, TOMORROW)
    proposal_count_yesterday = -1 #transaction_count(RewardProposal, YESTERDAY, TODAY)
    proposal_count_weekly = -1 #transaction_count(RewardProposal, MONDAY, NEXT_MONDAY)
    proposal_count_monthly = -1 #transaction_count(RewardProposal, FIRST_DAY_CURRENT_MONTH, FIRST_DAY_NEXT_MONTH)
    proposal_count_yearly = -1 #transaction_count(RewardProposal, FIRST_DAY_CURRENT_YEAR, FIRST_DAY_NEXT_YEAR)
    ### RewardPayment queries
    payment_query_today = -1 #claimed_proposal_payment(RewardProposal, RewardPayment, TODAY, TOMORROW)
    unclaimed_payment_query_today = -1 #unclaimed_proposal_payment(RewardProposal, RewardPayment, TODAY, TOMORROW)
    total_payment_query_today = -1 #total_proposal_payment(RewardProposal, RewardPayment, TODAY, TOMORROW)
    payment_query_yesterday = -1 #claimed_proposal_payment(RewardProposal, RewardPayment, YESTERDAY, TODAY)
    unclaimed_payment_yesterday = -1 #unclaimed_proposal_payment(RewardProposal, RewardPayment, YESTERDAY, TODAY)
    total_payment_query_yesterday = -1 #total_proposal_payment(RewardProposal, RewardPayment, YESTERDAY, TODAY)
    payment_query_weekly = -1 #claimed_proposal_payment(RewardProposal, RewardPayment, MONDAY, NEXT_MONDAY)
    unclaimed_payment_query_weekly = -1 #unclaimed_proposal_payment(RewardProposal, RewardPayment, MONDAY, NEXT_MONDAY)
    total_payment_query_weekly = -1 #total_proposal_payment(RewardProposal, RewardPayment, MONDAY, NEXT_MONDAY)
    payment_query_monthly = -1 #claimed_proposal_payment(RewardProposal, RewardPayment, FIRST_DAY_CURRENT_MONTH, FIRST_DAY_NEXT_MONTH)
    unclaimed_payment_query_monthly = -1 #unclaimed_proposal_payment(RewardProposal, RewardPayment, FIRST_DAY_CURRENT_MONTH, FIRST_DAY_NEXT_MONTH)
    total_payment_query_monthly = -1 #total_proposal_payment(RewardProposal, RewardPayment, FIRST_DAY_CURRENT_MONTH, FIRST_DAY_NEXT_MONTH)
    payment_query_yearly = -1 #claimed_proposal_payment(RewardProposal, RewardPayment, FIRST_DAY_CURRENT_YEAR, FIRST_DAY_NEXT_YEAR)
    unclaimed_payment_query_yearly = -1 #unclaimed_proposal_payment(RewardProposal, RewardPayment, FIRST_DAY_CURRENT_YEAR, FIRST_DAY_NEXT_YEAR)
    total_payment_query_yearly = -1 #total_proposal_payment(RewardProposal, RewardPayment, FIRST_DAY_CURRENT_YEAR, FIRST_DAY_NEXT_YEAR)
    payment_query_lifetime = -1 #claimed_lifetime(RewardProposal, RewardPayment)
    unclaimed_payment_lifetime = -1 #unclaimed_lifetime(RewardProposal, RewardPayment)
    total_payment_query_lifetime = -1 #total_lifetime(RewardProposal, RewardPayment)
    ### render template with the value
    return render_template('reporting/dashboard_proposals.html', \
        proposal_count_lifetime=proposal_count, proposal_count_today=proposal_count_today, proposal_count_yesterday=proposal_count_yesterday, \
        proposal_count_weekly=proposal_count_weekly, proposal_count_monthly=proposal_count_monthly, proposal_count_yearly=proposal_count_yearly, \
        payment_query_today=payment_query_today, unclaimed_payment_query_today=unclaimed_payment_query_today, total_payment_query_today=total_payment_query_today, \
        payment_query_yesterday=payment_query_yesterday, \
        unclaimed_payment_query_yesterday=unclaimed_payment_yesterday, payment_query_weekly=payment_query_weekly, \
        unclaimed_payment_query_weekly=unclaimed_payment_query_weekly, payment_query_monthly=payment_query_monthly, \
        unclaimed_payment_query_monthly=unclaimed_payment_query_monthly,payment_query_yearly=payment_query_yearly, \
        unclaimed_payment_query_yearly=unclaimed_payment_query_yearly,payment_query_lifetime=payment_query_lifetime, \
        unclaimed_payment_query_lifetime=unclaimed_payment_lifetime, \
        total_payment_query_yesterday=total_payment_query_yesterday,total_payment_query_weekly=total_payment_query_weekly, \
        total_payment_query_monthly=total_payment_query_monthly, total_payment_query_yearly=total_payment_query_yearly, \
        total_payment_query_lifetime=total_payment_query_lifetime)

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

def report_premio_txs(frequency):
    paydbtransactions_url = str('/admin/paydbtransaction/')
    paydbtransactions_filter = str('?flt1_0=')
    if frequency == 'lifetime':
        return redirect(str(paydbtransactions_url))
    if frequency == 'today':
        return redirect(str(paydbtransactions_url)+str(paydbtransactions_filter)+str(TODAY)+'+to+'+str(TOMORROW))
    if frequency == 'yesterday':
        return redirect(str(paydbtransactions_url)+str(paydbtransactions_filter)+str(YESTERDAY)+'+to+'+str(TODAY))
    if frequency == 'week':
        return redirect(str(paydbtransactions_url)+str(paydbtransactions_filter)+str(MONDAY)+'+to+'+str(NEXT_MONDAY))
    if frequency == 'month':
        return redirect(str(paydbtransactions_url)+str(paydbtransactions_filter)+str(FIRST_DAY_CURRENT_MONTH)+'+to+'+str(FIRST_DAY_NEXT_MONTH))
    if frequency == 'year':
        return redirect(str(paydbtransactions_url)+str(paydbtransactions_filter)+str(FIRST_DAY_CURRENT_YEAR)+'+to+'+str(FIRST_DAY_NEXT_YEAR))
    return redirect(str(paydbtransactions_url))

def report_proposal_txs(frequency):
    proposal_url = str('/admin/rewards')
    proposal_filter = str('?flt0_0=')
    if frequency == 'lifetime':
        return redirect(str(proposal_url))
    if frequency == 'today':
        return redirect(str(proposal_url)+str(proposal_filter)+str(TODAY)+'+to+'+str(TOMORROW))
    if frequency == 'yesterday':
        return redirect(str(proposal_url)+str(proposal_filter)+str(YESTERDAY)+'+to+'+str(TODAY))
    if frequency == 'week':
        return redirect(str(proposal_url)+str(proposal_filter)+str(MONDAY)+'+to+'+str(NEXT_MONDAY))
    if frequency == 'month':
        return redirect(str(proposal_url)+str(proposal_filter)+str(FIRST_DAY_CURRENT_MONTH)+'+to+'+str(FIRST_DAY_NEXT_MONTH))
    if frequency == 'year':
        return redirect(str(proposal_url)+str(proposal_filter)+str(FIRST_DAY_CURRENT_YEAR)+'+to+'+str(FIRST_DAY_NEXT_YEAR))
    return redirect(str(proposal_url))

def claimed_proposal_payment(table1, table2, start_date, end_date):
    result = table1.query.join(table2, table1.id==table2.reward_proposal_id)\
            .filter(and_(table1.date_authorized >= str(start_date),\
            table1.date_authorized < str(end_date))).filter(table2.status == 'sent_funds').with_entities(func.sum(table2.amount)).scalar()
    if not result:
        result = 0
    result = utils.int2asset(result)
    return result

def unclaimed_proposal_payment(table1, table2, start_date, end_date):
    result = table1.query.join(table2, table1.id==table2.reward_proposal_id)\
            .filter(and_(table1.date_authorized >= str(start_date),\
            table1.date_authorized < str(end_date))).filter(table2.status != 'sent_funds').with_entities(func.sum(table2.amount)).scalar()
    if not result:
        result = 0
    result = utils.int2asset(result)
    return result

def authorized_unclaimed_payment_proposal(table1, table2):
    result = table1.query.join(table2, table1.id==table2.reward_proposal_id)\
            .filter(table2.status != 'sent_funds').filter(table1.status == 'authorized')\
            .with_entities(func.sum(table2.amount)).scalar()
    if not result:
        result = 0
    return result

def total_proposal_payment(table1, table2, start_date, end_date):
    result = table1.query.join(table2, table1.id==table2.reward_proposal_id)\
            .filter(and_(table1.date_authorized >= str(start_date),\
            table1.date_authorized < str(end_date))).with_entities(func.sum(table2.amount)).scalar()
    if not result:
        result = 0
    result = utils.int2asset(result)
    return result

def claimed_lifetime(table1, table2):
    result = table1.query.join(table2, table1.id==table2.reward_proposal_id)\
            .filter(table2.status == 'sent_funds').with_entities(func.sum(table2.amount)).scalar()
    if not result:
        result = 0
    result = utils.int2asset(result)
    return result

def unclaimed_lifetime(table1, table2):
    result = table1.query.join(table2, table1.id==table2.reward_proposal_id)\
            .filter(table2.status != 'sent_funds').with_entities(func.sum(table2.amount)).scalar()
    if not result:
        result = 0
    result = utils.int2asset(result)
    return result

def total_lifetime(table1, table2):
    result = table1.query.join(table2, table1.id==table2.reward_proposal_id)\
            .with_entities(func.sum(table2.amount)).scalar()
    if not result:
        result = 0
    result = utils.int2asset(result)
    return result

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

def from_int_to_user_friendly(val, divisor, decimal_places=4):
    if not isinstance(val, int):
        return val
    val = val / divisor
    return round(val, decimal_places)

def dashboard_data_paydb():
    dasset_balances = dasset.account_balances()
    premio_stage_balance = -1
    premio_stage_account = 'blah'
    user = User.from_email(db.session, premio_stage_account)
    if user:
        premio_stage_balance = -1
    total_balance = -1
    claimable_rewards = -1 #authorized_unclaimed_payment_proposal(RewardProposal, RewardPayment)
    # return data
    return {"premio_stage_balance": premio_stage_balance, "premio_stage_account": premio_stage_account, \
            "total_balance": total_balance, "claimable_rewards": claimable_rewards, "dasset_balances": dasset_balances}

@reporting.route("/dashboard")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard():
    return redirect('dashboard_general')

@reporting.route("/dashboard_general")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_general():
    data = dashboard_data_paydb()
    data["premio_stage_balance"] = utils.int2asset(data["premio_stage_balance"])
    data["total_balance"] = utils.int2asset(data["total_balance"])
    data["claimable_rewards"] = utils.int2asset(data["claimable_rewards"])
    return report_dashboard_premio(data["premio_stage_balance"], data["premio_stage_account"], data["total_balance"], data["claimable_rewards"], data["dasset_balances"])

@reporting.route("/dashboard_report_proposals")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_report_proposals():
    return report_dashboard_proposals()

@reporting.route("/dashboard_report_premio")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_report_premio():
    data = dashboard_data_paydb()
    data["premio_stage_balance"] = utils.int2asset(data["premio_stage_balance"])
    data["total_balance"] = utils.int2asset(data["total_balance"])
    data["claimable_rewards"] = utils.int2asset(data["claimable_rewards"])
    return report_dashboard_premio(data["premio_stage_balance"], data["premio_stage_account"], data["total_balance"], data["claimable_rewards"], data["dasset_balances"])

    ### List username with their balances
@reporting.route("/dashboard_user_balance")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_user_balance():
    return report_user_balance()

### Premio Txs Dashboard
@reporting.route("/dashboard_premio_tx_today")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_premio_tx_today():
    today = str('today')
    return report_premio_txs(today)

@reporting.route("/dashboard_premio_tx_yesterday")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_premio_tx_yesterday():
    yesterday = str('yesterday')
    return report_premio_txs(yesterday)

@reporting.route("/dashboard_premio_tx_week")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_premio_tx_week():
    week = str('week')
    return report_premio_txs(week)

@reporting.route("/dashboard_premio_tx_month")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_premio_tx_month():
    month = str('month')
    return report_premio_txs(month)

@reporting.route("/dashboard_premio_tx_year")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_premio_tx_year():
    year = str('year')
    return report_premio_txs(year)

@reporting.route("/dashboard_premio_tx_lifetime")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_premio_tx_lifetime():
    lifetime = str('lifetime')
    return report_premio_txs(lifetime)

### RewardProposal Dashboard:
@reporting.route("/dashboard_proposal_tx_today")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_proposal_tx_today():
    today = str('today')
    return report_proposal_txs(today)

@reporting.route("/dashboard_proposal_tx_yesterday")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_proposal_tx_yesterday():
    yesterday = str('yesterday')
    return report_proposal_txs(yesterday)

@reporting.route("/dashboard_proposal_tx_week")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_proposal_tx_week():
    week = str('week')
    return report_proposal_txs(week)

@reporting.route("/dashboard_proposal_tx_month")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_proposal_tx_month():
    month = str('month')
    return report_proposal_txs(month)

@reporting.route("/dashboard_proposal_tx_year")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_proposal_tx_year():
    year = str('year')
    return report_proposal_txs(year)

@reporting.route("/dashboard_proposal_tx_lifetime")
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def dashboard_proposal_tx_lifetime():
    lifetime = str('lifetime')
    return report_proposal_txs(lifetime)

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
