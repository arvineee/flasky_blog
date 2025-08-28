import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-key")
    SQLALCHEMY_DATABASE_URI = "sqlite:///database.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSiWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_USERNAME")
