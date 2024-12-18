import os
import psycopg2

base_dir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.urandom(16) 

    # Database URI
    SQLALCHEMY_DATABASE_URI =  'postgresql://arvine:qcMUZd5KPu99si45RXw7RaetkO5BAINb@dpg-ctha3b0gph6c73dad1n0-a.oregon-postgres.render.com/arval'
    SQLALCHEMY_TRACK_MODIFICATIONS = False  
    
    conn = psycopg2.connect(
    dbname="arval",
    user="arvine",
    password="qcMUZd5KPu99si45RXw7RaetkO5BAINb",
    host="dpg-ctha3b0gph6c73dad1n0-a.oregon-postgres.render.com"
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
