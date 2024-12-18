import os
import psycopg2

base_dir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.urandom(16) 

    # Database URI
    SQLALCHEMY_DATABASE_URI =  'postgresql://Arval_database_owner:jCn7EabY5oTz@ep-round-morning-a68wihjp.us-west-2.aws.neon.tech/Arval_database?sslmode=require'
    SQLALCHEMY_TRACK_MODIFICATIONS = False  
    
    conn = psycopg2.connect(
    dbname="Arval_database",
    user="Arval_database_owner",
    password="jCn7EabY5oTz",
    host= "ep-round-morning-a68wihjp.us-west-2.aws.neon.tech"
)

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
