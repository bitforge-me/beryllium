from datetime import timedelta

# Database settings
SQLALCHEMY_ECHO = False

# Flask-Security config
SECURITY_URL_PREFIX = "/admin"
SECURITY_PASSWORD_HASH = "pbkdf2_sha512"

# Flask-Security URLs, overridden because they don't put a / at the end
SECURITY_LOGIN_URL = "/login/"
SECURITY_LOGOUT_URL = "/logout/"
SECURITY_REGISTER_URL = "/register/"
SECURITY_VERIFY_URL = "/verify/"

SECURITY_POST_LOGIN_VIEW = "/"
SECURITY_POST_LOGOUT_VIEW = "/"
SECURITY_POST_REGISTER_VIEW = "/"

# Flask-Security features
SECURITY_CONFIRMABLE = True
SECURITY_TRACKABLE = True
SECURITY_REGISTERABLE = True
SECURITY_RECOVERABLE = True
SECURITY_CHANGEABLE = True
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECURITY_TWO_FACTOR = True
SECURITY_TWO_FACTOR_ENABLED_METHODS = ['email'] # TODO - change to ['authenticator'] when all vulnerable paths updated
SECURITY_TOTP_ISSUER = 'beryllium'
SECURITY_FRESHNESS = timedelta(minutes=30)
SECURITY_FRESHNESS_GRACE_PERIOD = timedelta(seconds=300)
SECURITY_PASSWORD_LENGTH_MIN = 8
SECURITY_PASSWORD_COMPLEXITY_CHECKER = 'zxcvbn'
SECURITY_PASSWORD_CHECK_BREACHED = 'strict'
SECURITY_PASSWORD_BREACHED_COUNT = 1
