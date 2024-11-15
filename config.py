import os

base_dir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.urandom(16) 
    
    # Database URI
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False  
    
    # Upload folder for storing files
    UPLOAD_FOLDER = os.path.join(base_dir, 'app/static/images')
    
    # Flask-Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'kiruifelix03@gmail.com'
    MAIL_PASSWORD = 'rjdzvecxkiitmtco'
    MAIL_DEFAULT_SENDER = 'kiruifelix03@gmail.com'
