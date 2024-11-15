import os

base_dir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')  
    
    # Database URI
    SQLALCHEMY_DATABASE_URI = os.environ.get('DB_URL')  #
    SQLALCHEMY_TRACK_MODIFICATIONS = False  
    
    # Upload folder for storing files
    UPLOAD_FOLDER = os.path.join(base_dir, 'app/static/images')
    
    # Flask-Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')  
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)  
