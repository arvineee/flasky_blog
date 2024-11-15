from flask import Flask
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_ckeditor import CKEditor
from config import Config
from dotenv import load_dotenv
from flask_mail import Mail
import os

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions after app is created
bootstrap = Bootstrap(app)
ckeditor = CKEditor(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)
mail =  Mail(app)

login_manager.login_view = 'login'

# Register blueprint after app and extensions are initialized
from app.admin_routes import admin_bp
app.register_blueprint(admin_bp)

# Import routes and models after blueprint registration
from app import routes, models
