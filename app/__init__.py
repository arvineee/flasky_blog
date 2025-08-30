import logging
from flask import Flask, g, request, render_template
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_ckeditor import CKEditor
from datetime import datetime
from config import Config
from dotenv import load_dotenv
import getpass
import click
from flask.cli import with_appcontext
import os
from .ddos_protection import ddos_protection

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
bootstrap = Bootstrap()
ckeditor = CKEditor()
migrate = Migrate()
mail = Mail()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Add custom escapejs filter
    @app.template_filter('escapejs')
    def escapejs_filter(value):
        """Escape characters for use in JavaScript strings."""
        if value is None:
            return ''
        value = str(value)
        escape_map = {
            '\\': '\\\\',
            '"': '\\"',
            "'": "\\'",
            '\n': '\\n',
            '\r': '\\r',
            '\t': '\\t',
            '<': '\\u003C',
            '>': '\\u003E',
            '&': '\\u0026',
            '=': '\\u003D',
            '-': '\\u002D',
            ';': '\\u003B',
        }
        return ''.join(escape_map.get(c, c) for c in value)

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    bootstrap.init_app(app)
    ckeditor.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    # Initialize DDoS protection AFTER other extensions
    ddos_protection.init_app(app)

    login_manager.login_view = 'main.login'
    logger.debug("Flask app and extensions initialized")

    # Import models here to avoid circular import
    from app import models
    from app.routes import main
    from app.admin_routes import admin_bp
    from app.newsletter_route import newsletter_bp

    # Register blueprints
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(newsletter_bp)
    app.register_blueprint(main)
    logger.debug("Blueprints registered: admin_bp, newsletter_bp, main_bp")

    UPLOAD_FOLDER = os.path.join(app.root_path, "static", "images")
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

    # Create video upload folder if it doesn't exist
    VIDEO_UPLOAD_FOLDER = os.path.join(app.root_path, "static", "videos")
    os.makedirs(VIDEO_UPLOAD_FOLDER, exist_ok=True)
    app.config["VIDEO_UPLOAD_FOLDER"] = VIDEO_UPLOAD_FOLDER

    # Request timing and traffic logging
    from app.models import TrafficStats, Category

    @app.before_request
    def start_timer():
        g.start_time = datetime.utcnow()
        logger.debug("Request started: endpoint=%s, ip=%s, method=%s, start_time=%s",
                     request.endpoint, request.remote_addr, request.method, g.start_time)

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
            logger.exception("Traffic logging error")
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        logger.error("CSRF error on endpoint=%s, ip=%s: %s",
                     request.endpoint, request.remote_addr, e.description)
        return render_template('csrf_error.html', reason=e.description), 400

    # Inject current time and categories into templates
    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow()}

    @app.context_processor
    def inject_categories():
        categories = Category.query.filter_by(parent_id=None).order_by(Category.name).all()
        category_structure = []
        for cat in categories:
            subcats = Category.query.filter_by(parent_id=cat.id).order_by(Category.name).all()
            category_structure.append({'category': cat, 'subcategories': subcats})
        return dict(category_structure=category_structure)

    # CLI command to create admin - IMPROVED VERSION
    @app.cli.command("create-admin")
    @with_appcontext
    def create_admin():
        """Create a new admin user with proper validation"""
        from app.models import User
        
        print("=== Create a New Admin User ===")

        while True:
            username = input("Username: ").strip()
            if username:
                # Check if username already exists
                if User.query.filter_by(username=username).first():
                    print("Username already exists. Please choose a different one.")
                else:
                    break
            else:
                print("Username cannot be empty.")

        while True:
            email = input("Email: ").strip()
            if email:
                # Check if email already exists
                if User.query.filter_by(email=email).first():
                    print("Email already exists. Please use a different email.")
                else:
                    break
            else:
                print("Email cannot be empty.")

        while True:
            password = getpass.getpass("Password: ").strip()
            password_confirm = getpass.getpass("Confirm Password: ").strip()
            
            if not password:
                print("Password cannot be empty.")
                continue
                
            if len(password) < 6:
                print("Password must be at least 6 characters.")
                continue
                
            if password != password_confirm:
                print("Passwords do not match. Try again.")
            else:
                break

        # Create the admin user
        new_user = User(
            username=username,
            email=email,
            is_admin=True
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        try:
            db.session.commit()
            print(f"✅ Admin user '{username}' created successfully!")
            print(f"   Email: {email}")
            print(f"   Admin privileges: Yes")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error creating admin user: {e}")

    # CLI command to initialize database
    @app.cli.command("init-db")
    @with_appcontext
    def init_db():
        """Initialize the database with default categories"""
        from app.models import Category
        
        # Create default categories if they don't exist
        default_categories = [
            'Technology',
            'Science',
            'Art',
            'Sports',
            'Entertainment',
            'News',
            'Education',
            'Health',
            'Travel',
            'Food'
        ]
        
        for cat_name in default_categories:
            category = Category.query.filter_by(name=cat_name).first()
            if not category:
                category = Category(name=cat_name)
                db.session.add(category)
                print(f"Created category: {cat_name}")
        
        try:
            db.session.commit()
            print("Database initialized successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"Error initializing database: {e}")

    # CLI command to list all users
    @app.cli.command("list-users")
    @with_appcontext
    def list_users():
        """List all users in the database"""
        from app.models import User
        
        users = User.query.all()
        if not users:
            print("No users found in the database.")
            return
            
        print("=== Users ===")
        for user in users:
            admin_status = "Yes" if user.is_admin else "No"
            confirmed_status = "Yes" if user.is_confirmed else "No"
            print(f"ID: {user.id} | Username: {user.username} | Email: {user.email} | Admin: {admin_status} | Confirmed: {confirmed_status}")

    return app
