#!/usr/bin/python3

# pylint: disable=import-outside-toplevel
# pylint: disable=unbalanced-tuple-unpacking

import logging
import math
import time

import gevent
from flask import render_template, request, flash, jsonify
from flask_security import roles_accepted

from app_core import app, db, socketio
from models import FiatDeposit, User, Role, Topic, PushNotificationLocation, BrokerOrder
import utils
from fcm import FCM
from web_utils import bad_request, get_json_params, get_json_params_optional
import broker
import depwith
from api_endpoint import api
from reward_endpoint import reward
from reporting_endpoint import reporting
from payments_endpoint import payments
from kyc_endpoint import kyc
import websocket
# pylint: disable=unused-import
import admin

#jsonrpc = JSONRPC(app, "/api")
logger = logging.getLogger(__name__)
fcm = FCM(app.config["FIREBASE_CREDENTIALS"])

# blueprints
app.register_blueprint(api, url_prefix='/apiv1')
app.register_blueprint(reward, url_prefix='/reward')
app.register_blueprint(reporting, url_prefix='/reporting')
app.register_blueprint(payments, url_prefix='/payments')
app.register_blueprint(kyc, url_prefix='/kyc')

def process_email_alerts():
    with app.app_context():
        #utils.email_notification_alert(logger, subject, msg, recipient)
        pass

def process_broker_orders():
    logger.info('process_broker_orders()')
    with app.app_context():
        orders = BrokerOrder.all_active(db.session)
        logger.info('num orders: %d', len(orders))
        for order in orders:
            broker.broker_order_update_and_commit(db.session, order)

def process_fiat_deposits():
    logger.info('process_fiat_deposits()')
    with app.app_context():
        deposits = FiatDeposit.all_active(db.session)
        logger.info('num deposits: %d', len(deposits))
        for deposit in deposits:
            depwith.fiat_deposit_update_and_commit(db.session, deposit)

#
# Jinja2 filters
#

@app.template_filter()
def int2asset(num):
    return utils.int2asset(num)

#
# Flask views
#

@app.route("/")
def index():
    return render_template("index.html")

# https://gis.stackexchange.com/a/2964
def meters_to_lat_lon_displacement(meters, origin_latitude):
    lat = meters / 111111
    lon = meters / (111111 * math.cos(math.radians(origin_latitude)))
    return lat, lon

@app.route("/push_notifications", methods=["GET", "POST"])
@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
def push_notifications():
    type_ = ''
    topic = ''
    title = ''
    body = ''
    image = ''
    html = ''
    location = ''
    registration_token = ''
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        image = request.form["image"]
        html = request.form["html"]
        try:
            type_ = request.form["type"]
            if type_ == "topic":
                topic = request.form["topic"]
                fcm.send_to_topic(topic, title, body, image, html)
                flash(f"sent push notification ({topic})", "success")
            elif type_ == "location":
                location = request.form["location"]
                parts = location.split(',')
                if len(parts) != 4:
                    raise Exception('invalid location parameter')
                latitude, longitude, max_dist_meters, max_age_minutes = parts
                latitude = float(latitude)
                longitude = float(longitude)
                max_dist_meters = int(max_dist_meters)
                max_age_minutes = int(max_age_minutes)
                max_lat_delta, max_long_delta = meters_to_lat_lon_displacement(max_dist_meters, latitude)
                tokens = PushNotificationLocation.tokens_at_location(db.session, latitude, max_lat_delta, longitude, max_long_delta, max_age_minutes)
                tokens = [x.fcm_registration_token for x in tokens]
                fcm.send_to_tokens(tokens, title, body, image, html)
                count = len(tokens)
                flash(f"sent push notification ({count} devices)", "success")
            else:
                registration_token = request.form["registration_token"]
                fcm.send_to_tokens([registration_token], title, body, image, html)
                flash("sent push notification", "success")
        except Exception as e: # pylint: disable=broad-except
            flash(str(e.args[0]), "danger")
    topics = Topic.topic_list(db.session)
    return render_template("push_notifications.html", topics=topics, type_=type_, topic=topic, location=location, title=title, body=body, image=image, html=html, registration_token=registration_token)

@app.route("/push_notifications_register", methods=["POST"])
def push_notifications_register():
    content = request.get_json(force=True)
    if content is None:
        return bad_request("failed to decode JSON object")
    params, err_response = get_json_params(content, ["registration_token"])
    if err_response:
        return err_response
    registration_token, = params
    latitude, longitude = get_json_params_optional(content, ["latitude", "longitude"])
    topics = Topic.topic_list(db.session)
    fcm.subscribe_to_topics(registration_token, topics)
    if latitude and longitude:
        latitude = float(latitude)
        longitude = float(longitude)
        push_location = PushNotificationLocation.from_token(db.session, registration_token)
        if push_location:
            push_location.update(latitude, longitude)
        else:
            push_location = PushNotificationLocation(registration_token, latitude, longitude)
        db.session.add(push_location)
        db.session.commit()
    return jsonify(dict(result="ok"))

@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
@app.route('/test_email', methods=['GET', 'POST'])
def test_email():
    recipient = ''
    subject = ''
    message = ''
    if request.method == 'POST':
        recipient = request.form['recipient']
        subject = request.form['subject']
        message = request.form['message']
        if utils.send_email(logger, subject, message, recipient):
            flash('Email sent', 'success')
        else:
            flash('Email failed', 'danger')
    return render_template('test_email.html', recipient=recipient, subject=subject, message=message)

@roles_accepted(Role.ROLE_ADMIN, Role.ROLE_FINANCE)
@app.route('/test_ws', methods=['GET', 'POST'])
def test_ws():
    recipient = ''
    event = ''
    events = ['user_info_update', 'broker_order_update', 'broker_order_new']
    if request.method == 'POST':
        recipient = request.form['recipient']
        event = request.form['event']
        if event == 'user_info_update':
            user = User.from_email(db.session, recipient)
            if user:
                websocket.user_info_event(user)
                flash('Event sent', 'success')
            else:
                flash('User not found', 'danger')
        elif event == 'broker_order_update':
            order = BrokerOrder.from_token(db.session, recipient)
            if order:
                websocket.broker_order_update_event(order)
                flash('Event sent', 'success')
            else:
                flash('Order not found', 'danger')
        else:
            flash('Event not yet implemented', 'danger')
    return render_template('test_ws.html', recipient=recipient, event=event, events=events)

#
# gevent class
#

class WebGreenlet():

    def __init__(self, exception_func, addr="0.0.0.0", port=5000):
        self.addr = addr
        self.port = port
        self.runloop_greenlet = None
        self.process_periodic_events_greenlet = None
        self.exception_func = exception_func

    def start(self):
        def runloop():
            logger.info("WebGreenlet runloop started")
            logger.info("WebGreenlet webserver starting (addr: %s, port: %d)", self.addr, self.port)
            socketio.run(app, host=self.addr, port=self.port)

        def process_periodic_events_loop():
            current = int(time.time())
            email_alerts_timer_last = current
            broker_orders_timer_last = current
            fiat_deposits_timer_last = current
            while True:
                current = time.time()
                if current - email_alerts_timer_last > 1800:
                    gevent.spawn(process_email_alerts)
                    email_alerts_timer_last += 1800
                if current - broker_orders_timer_last > 300:
                    gevent.spawn(process_broker_orders)
                    broker_orders_timer_last += 300
                if current - fiat_deposits_timer_last > 300:
                    gevent.spawn(process_fiat_deposits)
                    fiat_deposits_timer_last += 300
                gevent.sleep(5)

        def start_greenlets():
            logger.info("starting WebGreenlet runloop...")
            self.runloop_greenlet.start()
            self.process_periodic_events_greenlet.start()

        # create greenlet
        self.runloop_greenlet = gevent.Greenlet(runloop)
        self.process_periodic_events_greenlet = gevent.Greenlet(process_periodic_events_loop)
        if self.exception_func:
            self.runloop_greenlet.link_exception(self.exception_func)
        # start greenlets
        gevent.spawn(start_greenlets)

    def stop(self):
        self.runloop_greenlet.kill()
        self.process_periodic_events_greenlet.kill()
        gevent.joinall([self.runloop_greenlet, self.process_periodic_events_greenlet])

def run():
    # setup logging
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(handler)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

    web_greenlet = WebGreenlet(None)
    web_greenlet.start()

    while 1:
        gevent.sleep(1)

    web_greenlet.stop()

if __name__ == "__main__":
    run()
