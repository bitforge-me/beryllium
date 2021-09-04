import os
import re
import io
import decimal
import base64
import secrets
import string

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From, Attachment, FileContent, FileName, FileType, Disposition, ContentId
from flask import url_for
import qrcode
import qrcode.image.svg
import qrcode.image.pil

from app_core import app

def int2asset(num):
    if num is None:
        return '!ERR!'
    num = decimal.Decimal(num)/100
    return '{num:0.2f}'.format(num=num)

def _attachment(b64data, mime_type, filename, content_id, disposition='attachment'):
    attachment = Attachment()
    attachment.file_content = FileContent(b64data)
    attachment.file_type = FileType(mime_type)
    attachment.file_name = FileName(filename)
    attachment.disposition = Disposition(disposition)
    attachment.content_id = ContentId(content_id)
    return attachment

def _attachment_inline(b64data, mime_type, filename, content_id):
    return _attachment(b64data, mime_type, filename, content_id, 'inline')

def send_email(logger, subject, msg, recipient=None, attachment=None):
    if not recipient:
        recipient = app.config["ADMIN_EMAIL"]
    from_email = From(app.config["FROM_EMAIL"], app.config["FROM_NAME"])
    template_path = "templates/email_template.html"
    with open(os.path.join(os.path.dirname(__file__), template_path), 'r', encoding='utf-8') as input_file:
        html = input_file.read()
    logo_src = app.config["LOGO_EMAIL_SRC"]
    html = html.replace("<LOGOSRC/>", logo_src).replace("<EMAILCONTENT/>", msg)
    message = Mail(from_email=from_email, to_emails=recipient, subject=subject, html_content=html)
    if attachment:
        message.attachment = attachment
    try:
        sg = SendGridAPIClient(app.config["MAIL_SENDGRID_API_KEY"])
        sg.send(message)
    except Exception as ex: # pylint: disable=broad-except
        logger.error(f"email '{subject}': {ex}")

def email_exception(logger, msg):
    send_email(logger, "premio stage exception", msg)

def email_user_create_request(logger, req, minutes_expiry):
    url = url_for("api.user_registration_confirm", token=req.token, _external=True)
    msg = f"You have a pending user registration waiting!<br/><br/>Confirm your registration <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, "Confirm your registration", msg, req.email)

def email_user_update_email_request(logger, req, minutes_expiry):
    url = url_for("api.user_update_email_confirm", token=req.token, _external=True)
    msg = f"You have a pending update email request waiting!<br/><br/>Confirm your new email <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, "Confirm your update email request", msg, req.email)

def email_api_key_request(logger, req, minutes_expiry):
    url = url_for("api.api_key_confirm", token=req.token, secret=req.secret, _external=True)
    msg = f"You have a pending email login request waiting!<br/><br/>Confirm your email login <a href='{url}'>here</a><br/><br/>Confirm within {minutes_expiry} minutes"
    send_email(logger, "Confirm your email login request", msg, req.user.email)

def email_referral(logger, referral):
    shop_name = app.config["REFERRAL_STORE_NAME"]
    qrcode_b64 = qrcode_pngb64_create(referral.token, box_size=4)
    ecom_link = app.config["REFERRAL_ECOMMERCE_URL"]
    if ecom_link:
        ecom_link += f"?premio_referral={referral.token}"
    sender_name = referral.user.first_name
    if not sender_name:
        sender_name = referral.user.email
    asset_name = app.config["ASSET_NAME"]
    spend = int2asset(referral.recipient_min_spend)
    spend_asset = app.config["REFERRAL_SPEND_ASSET"]
    gift = f"Spend {spend} {spend_asset} and recieve {int2asset(referral.reward_recipient)} {asset_name}"
    if referral.reward_recipient_type == referral.REWARD_TYPE_PERCENT:
        gift = f"Spend {spend} {spend_asset} or more and recieve {referral.reward_recipient}% off your purchase price"
    msg = f"You have been recieved a referral from {sender_name}<br/><br/>{gift}<br/<br/><img src=\"cid:qrcode\"><br/><br/>"
    if ecom_link:
        msg += ecom_link
    attachment = _attachment_inline(qrcode_b64, 'image/png', 'qrcode.png', 'qrcode')
    send_email(logger, f"{shop_name} Referral", msg, referral.recipient, attachment)

def email_notification_alert(logger, subject, msg, recipient):
    send_email(logger, subject, msg, recipient=recipient)

def email_payout_group_notification(logger, group):
    recipient = app.config['PAYOUT_GROUP_EMAIL']
    server_name = app.config['SERVER_NAME']
    subject = '%s payout' % server_name
    html_content = '%d payout requests<br/><br/>' % len(group.requests)
    if len(group.requests) > 0:
        all_url = url_for('payments.payout_group', token=group.token, secret=group.secret, _external=True)
        html_content += '<a href="%s">payout group: %s</a>' % (all_url, group.token)
    send_email(logger, subject, html_content, recipient=recipient)

def generate_key(chars=10, upper=True):
    alphabet = string.ascii_letters + string.digits
    if upper:
        alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(chars))

def is_email(val):
    return re.match("[^@]+@[^@]+\.[^@]+", val) # pylint: disable=anomalous-backslash-in-string

def is_mobile(val):
    return val.isnumeric()

def qrcode_create(factory, data, box_size):
    img = qrcode.make(data, image_factory=factory, box_size=box_size)
    output = io.BytesIO()
    img.save(output)
    return output

def qrcode_svg_create(data, box_size=10):
    factory = qrcode.image.svg.SvgPathImage
    output = qrcode_create(factory, data, box_size)
    svg = output.getvalue().decode('utf-8')
    return svg

def qrcode_pngb64_create(data, box_size=10):
    factory = qrcode.image.pil.PilImage
    output = qrcode_create(factory, data, box_size)
    b64 = base64.b64encode(output.getvalue()).decode('utf-8')
    return b64
