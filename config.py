import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-key-for-development-only")
    
    # Email
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_USERNAME")
    
    # Redis
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # GeoIP
    GEOIP_DATABASE_PATH = os.environ.get('GEOIP_DATABASE_PATH')
    
    # Advanced Protection Settings
    PROTECTION_MODE = os.environ.get('PROTECTION_MODE', 'active')
    REQUEST_LIMIT = int(os.environ.get('REQUEST_LIMIT', 500))
    WINDOW_SIZE = int(os.environ.get('WINDOW_SIZE', 60))
    BAN_TIME = int(os.environ.get('BAN_TIME', 300))
    AUTO_BAN = os.environ.get('AUTO_BAN', 'true').lower() == 'true'
    WAF_ENABLED = os.environ.get('WAF_ENABLED', 'true').lower() == 'true'
    JS_CHALLENGE_ENABLED = os.environ.get('JS_CHALLENGE_ENABLED', 'true').lower() == 'true'
    CAPTCHA_ENABLED = os.environ.get('CAPTCHA_ENABLED', 'true').lower() == 'true'
    BEHAVIORAL_ANALYSIS_ENABLED = os.environ.get('BEHAVIORAL_ANALYSIS_ENABLED', 'true').lower() == 'true'
    GEO_BLOCKING_ENABLED = os.environ.get('GEO_BLOCKING_ENABLED', 'false').lower() == 'true'
    API_RATE_LIMITING_ENABLED = os.environ.get('API_RATE_LIMITING_ENABLED', 'true').lower() == 'true'
    SYN_FLOOD_THRESHOLD = int(os.environ.get('SYN_FLOOD_THRESHOLD', 500))
    
    # External Services
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
    CLOUDFLARE_API_KEY = os.environ.get('CLOUDFLARE_API_KEY')
    RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY')
    
    # Application
    DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'
    ENV = os.environ.get('ENV', 'production')
