import logging
import json

from flask import request
from flask_socketio import Namespace, emit, join_room, leave_room

from app_core import db, socketio
from web_utils import check_auth

logger = logging.getLogger(__name__)
ws_sids = {}

NS = '/events'

#
# Helper functions
#

def user_info_dict(api_key, all_info):
    user = api_key.user
    roles = []
    perms = []
    kyc_validated = None
    kyc_url = None
    if all_info:
        roles = [role.name for role in user.roles]
        perms = [perm.name for perm in api_key.permissions]
        kyc_validated = user.kyc_validated()
        kyc_url = user.kyc_url()
    return dict(first_name=user.first_name, last_name=user.last_name, mobile_number=user.mobile_number, address=user.address, email=user.email, photo=user.photo, photo_type=user.photo_type, roles=roles, permissions=perms, kyc_validated=kyc_validated, kyc_url=kyc_url)

def user_info_dict_ws(user):
    roles = [role.name for role in user.roles]
    kyc_validated = user.kyc_validated()
    kyc_url = user.kyc_url()
    return dict(first_name=user.first_name, last_name=user.last_name, mobile_number=user.mobile_number, address=user.address, email=user.email, photo=user.photo, photo_type=user.photo_type, roles=roles, kyc_validated=kyc_validated, kyc_url=kyc_url)

#
# Websocket events
#

def user_info_event(user):
    data = json.dumps(user_info_dict_ws(user))
    socketio.emit("user_info_update", data, json=True, room=user.email, namespace=NS)

def broker_order_update_event(broker_order):
    data = json.dumps(broker_order.to_json())
    socketio.emit("broker_order_update", data, json=True, room=broker_order.user.email, namespace=NS)

def broker_order_new_event(broker_order):
    data = json.dumps(broker_order.to_json())
    socketio.emit("broker_order_new", data, json=True, room=broker_order.user.email, namespace=NS)

class EventsNamespace(Namespace):

    def on_error(self, err):
        logger.error(err)

    def on_connect(self):
        logger.info("connect sid: %s", request.sid)

    def on_auth(self, auth):
        if not isinstance(auth, dict):
            try:
                auth = json.loads(auth)
            except: # pylint: disable=bare-except
                emit("info", "invalid json", namespace=NS)
                return
        if "api_key" not in auth:
            emit("info", "'api_key' param missing", namespace=NS)
            return
        if "nonce" not in auth:
            emit("info", "'nonce' param missing", namespace=NS)
            return
        if "signature" not in auth:
            emit("info", "'signature' param missing", namespace=NS)
            return
        # check auth
        res, reason, api_key = check_auth(db.session, auth["api_key"], auth["nonce"], auth["signature"], str(auth["nonce"]))
        if res:
            emit("info", "authenticated!", namespace=NS)
            # join room and store user
            logger.info("join room for email: %s", api_key.user.email)
            join_room(api_key.user.email)
            # store sid -> email map
            ws_sids[request.sid] = api_key.user.email
        else:
            api_key = auth["api_key"]
            emit("info", f"failed authentication ({api_key}): {reason}", namespace=NS)
            logger.info("failed authentication (%s): %s", api_key, reason)

    def on_disconnect(self):
        logger.info("disconnect sid: %s", request.sid)
        if request.sid in ws_sids:
            # remove sid -> email map
            email = ws_sids[request.sid]
            logger.info("leave room for email: %s", email)
            leave_room(email)
            del ws_sids[request.sid]

socketio.on_namespace(EventsNamespace(NS))
