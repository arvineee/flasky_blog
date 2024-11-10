import os

base_dir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DB_URL')
    UPLOAD_FOLDER = os.path.join(base_dir, 'static/images')
    SQLALCHEMY_TRACK_MODIFICATIONS = False


