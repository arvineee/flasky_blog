from flask import Flask, request, g, render_template
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect, CSRFError
from config import Config
from dotenv import load_dotenv
import os
from flask_ckeditor import CKEditor
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
csrf = CSRFProtect(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
ckeditor = CKEditor(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)
mail = Mail(app)

login_manager.login_view = 'login'

# Traffic logging model
from app.models import TrafficStats

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.before_request
def start_timer():
    g.start_time = datetime.utcnow()

@app.after_request
def log_traffic(response):
    try:
        if request.endpoint and request.endpoint != 'static':
            end_time = datetime.utcnow()
            duration = (end_time - g.start_time).total_seconds()
            visitor_ip = request.remote_addr

            traffic_entry = TrafficStats.query.filter_by(
                endpoint=request.endpoint,
                visitor_ip=visitor_ip
            ).first()

            if traffic_entry:
                traffic_entry.visitor_count += 1
                traffic_entry.total_time_spent += duration
                traffic_entry.timestamp = datetime.utcnow()
            else:
                traffic_entry = TrafficStats(
                    endpoint=request.endpoint,
                    visitor_ip=visitor_ip,
                    visitor_count=1,
                    total_time_spent=duration,
                    timestamp=datetime.utcnow()
                )
                db.session.add(traffic_entry)

            db.session.commit()
    except Exception as e:
        app.logger.error(f"Traffic logging error: {str(e)}")
    return response

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

# Dummy endpoint for CSRF initialization
@app.route('/csrf-init')
def csrf_init():
    return '', 204

# Register blueprints
from app.admin_routes import admin_bp
from app.newsletter_route import newsletter_bp

app.register_blueprint(admin_bp)
app.register_blueprint(newsletter_bp)

# Import routes and models after blueprints
from app import routes, models
