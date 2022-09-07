import logging

from flask import Blueprint, request, render_template, flash, redirect, make_response, abort

from app_core import app, limiter, talisman, csp
from email_utils import email_catastrophic_error, send_email
import httpreq

logger = logging.getLogger(__name__)
support = Blueprint('support', __name__, template_folder='templates/support')
limiter.limit("100/minute")(support)

csp_support = csp.copy()
csp_support['script-src'] += " https://challenges.cloudflare.com"
csp_support['frame-src'] += " https://challenges.cloudflare.com"

SUPPORT_EMAIL = app.config['SUPPORT_EMAIL']
CAPTCHA_SECRETKEY = app.config['CAPTCHA_SECRETKEY']
CAPTCHA_SITEKEY = app.config['CAPTCHA_SITEKEY']

def _is_human(captcha_response):
    ''' Validates recaptcha response using cloudflare turnstile - https://developers.cloudflare.com/turnstile'''
    try:
        payload = dict(response=captcha_response, secret=CAPTCHA_SECRETKEY)
        r = httpreq.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=payload)
        r.raise_for_status()
        return r.json()['success']
    except Exception as e:
        logger.error('failed to validate recaptcha', e)
    return False

#
# Public kyc endpoints
#

@support.route('/', methods=['GET', 'POST'])
@talisman(content_security_policy=csp_support)
def support_ep():
    if not SUPPORT_EMAIL:
        email_catastrophic_error('no support email configured')
        return 'no support email configured'
    email = request.args.get('email', '')
    msg = ''
    if request.method == 'POST':
        if request.form['msg'] and request.form['email']:
            msg = request.form['msg']
            email = request.form['email']
            captcha_response = request.form.get('cf-turnstile-response')
            if not CAPTCHA_SITEKEY or _is_human(captcha_response):
                msg_full = f'from {email}<br><br>--------<br><br>{msg}'
                send_email('support request', msg_full, SUPPORT_EMAIL)
                flash('Support request sent!', 'success')
            else:
                flash('CAPTCHA failed', 'danger')
    return render_template('support.html', site_key=CAPTCHA_SITEKEY, email=email, msg=msg)
