import os

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-key")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_USERNAME")
    
    # Advanced Protection Settings
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    GEOIP_DATABASE_PATH = os.environ.get('GEOIP_DATABASE_PATH', None)

    # Protection settings (defaults)
    PROTECTION_MODE = 'active'
    REQUEST_LIMIT = 100
    WINDOW_SIZE = 60
    BAN_TIME = 300
    AUTO_BAN = True
    WAF_ENABLED = True
    JS_CHALLENGE_ENABLED = True
