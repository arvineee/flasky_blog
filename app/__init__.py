from flask import Flask,request,g
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

from app.models import TrafficStats
from datetime import datetime


@app.before_request
def start_timer():
    if request.endpoint and request.endpoint != 'static':
        g.start_time = datetime.utcnow()

@app.after_request
def log_traffic(response):
    if request.endpoint and request.endpoint != 'static':
        try:
            end_time = datetime.utcnow()
            duration = (end_time - g.start_time).total_seconds()
            visitor_ip = request.remote_addr

            # Check if the record exists for this visitor and endpoint
            traffic_entry = TrafficStats.query.filter_by(
                endpoint=request.endpoint,
                visitor_ip=visitor_ip,
            ).first()

            if traffic_entry:
                # Update existing record
                traffic_entry.visitor_count += 1
                traffic_entry.total_time_spent += duration
                traffic_entry.timestamp = datetime.utcnow()  # Update the timestamp
            else:
                # Create a new record
                traffic_entry = TrafficStats(
                    endpoint=request.endpoint,
                    visitor_ip=visitor_ip,
                    visitor_count=1,
                    total_time_spent=duration,
                    timestamp=datetime.utcnow(),
                )
                db.session.add(traffic_entry)

            db.session.commit()
        except Exception as e:
            app.logger.error(f"Error logging traffic: {e}")
    return response

# Register blueprint after app and extensions are initialized
from app.admin_routes import admin_bp
app.register_blueprint(admin_bp)

# Import routes and models after blueprint registration
from app import routes, models
