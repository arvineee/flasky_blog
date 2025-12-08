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
import atexit
import signal
from .ddos_protection import ddos_protection
from app.advanced_protection import advanced_protection
import geoip2.database
from datetime import datetime

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
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
            '"': '\"',
            "'": "\'",
            '\n': '\n',
            '\r': '\r',
            '\t': '\t',
            '<': '\u003C',
            '>': '\u003E',
            '&': '\u0026',
            '=': '\u003D',
            '-': '\u002D',
            ';': '\u003B',
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
    advanced_protection.init_app(app)

    # Initialize DDoS protection AFTER other extensions
    ddos_protection.init_app(app)

    login_manager.login_view = 'main.login'
    logger.debug("Flask app and extensions initialized")

    # Import models here to avoid circular import
    from app import models
    from app.routes import main
    from app.admin_routes import admin_bp
    from app.newsletter_route import newsletter_bp
    from app.api_routes import api_bp
    from app.advanced_protection import advanced_protection_bp
    from app.ads_routes import ads_bp

    # Register blueprints
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(newsletter_bp)
    app.register_blueprint(main)
    app.register_blueprint(api_bp)
    app.register_blueprint(ads_bp, url_prefix="/ads")
    csrf.exempt(api_bp)
    logger.debug("Blueprints registered: admin_bp, newsletter_bp, main_bp")

    # Setup upload folders
    UPLOAD_FOLDER = os.path.join(app.root_path, "static", "images")
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

    VIDEO_UPLOAD_FOLDER = os.path.join(app.root_path, "static", "videos")
    os.makedirs(VIDEO_UPLOAD_FOLDER, exist_ok=True)
    app.config["VIDEO_UPLOAD_FOLDER"] = VIDEO_UPLOAD_FOLDER

    # Initialize GeoIP reader
    try:
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        GEOIP_DB_PATH = os.path.join(BASE_DIR, "geoip", "GeoLite2-Country.mmdb")
        
        app.config['GEOIP_DATABASE_PATH'] = GEOIP_DB_PATH
        
        if os.path.exists(GEOIP_DB_PATH):
            app.geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            logger.info("GeoIP database loaded successfully")
        else:
            logger.warning(f"GeoIP database file not found at {GEOIP_DB_PATH}")
            app.geoip_reader = None
    except Exception as e:
        logger.error(f"Failed to load GeoIP database: {str(e)}")
        app.geoip_reader = None

    # Redis automation for Termux
    def setup_redis():
        """Setup Redis server for Termux environment"""
        try:
            import redis
            import subprocess
            import time
            
            # Check if Redis is already running
            try:
                redis_client = redis.from_url(app.config['REDIS_URL'], socket_connect_timeout=2)
                redis_client.ping()
                logger.info("Redis server is already running")
                return True
            except (redis.ConnectionError, redis.BusyLoadingError):
                pass
            
            logger.warning("Redis server not running. Attempting to start for Termux...")
            
            # Check if Redis is installed
            try:
                subprocess.run(['redis-server', '--version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.error("Redis not installed in Termux. Install with: pkg install redis")
                return False
            
            # Start Redis server for Termux
            redis_process = subprocess.Popen(
                ['redis-server', '--save', '', '--appendonly', 'no'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            
            # Store process reference
            app.redis_process = redis_process
            time.sleep(3)
            
            # Verify Redis started
            redis_client = redis.from_url(app.config['REDIS_URL'], socket_connect_timeout=3)
            redis_client.ping()
            logger.info("Redis server started successfully in Termux")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Redis server: {e}")
            logger.warning("Running without Redis - some features may not work properly")
            return False

    # Setup Redis
    setup_redis()

    def stop_redis():
        """Stop Redis server when application exits"""
        if hasattr(app, 'redis_process'):
            try:
                os.killpg(os.getpgid(app.redis_process.pid), signal.SIGTERM)
                logger.info("Redis server stopped")
            except Exception as e:
                logger.error(f"Error stopping Redis: {e}")

    atexit.register(stop_redis)

    # Request timing and traffic logging
    from app.models import TrafficStats, Category

    @app.before_request
    def start_timer():
        """Start timer for request processing - only if not blocked by protection"""
        skip_paths = [
            '/login', '/register', '/static/', '/advanced-protection/',
            '/logout', '/reset_password', '/contact', '/admin/login'
        ]
        
        if any(request.path.startswith(path) for path in skip_paths):
            g.start_time = datetime.utcnow()
            return
        
        g.start_time = datetime.utcnow()
        logger.debug("Request started: endpoint=%s, ip=%s, method=%s, path=%s", 
                    request.endpoint, request.remote_addr, request.method, request.path)

    @app.after_request
    def log_traffic(response):
        """Log traffic statistics - handle cases where request was blocked"""
        try:
            if (hasattr(g, 'start_time') and 
                request.endpoint and 
                request.endpoint != 'static' and
                response.status_code != 429):
                
                end_time = datetime.utcnow()
                duration = (end_time - g.start_time).total_seconds()
                visitor_ip = request.remote_addr

                logger.debug(f"Logging traffic: {request.endpoint}, IP: {visitor_ip}, Duration: {duration:.2f}s")
                
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
            if hasattr(g, 'start_time') and response.status_code != 429:
                logger.exception("Traffic logging error")
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        logger.error("CSRF error on endpoint=%s, ip=%s: %s",
                    request.endpoint, request.remote_addr, e.description)
        return render_template('csrf_error.html', reason=e.description), 400


    
    @app.template_filter('format_number')
    def format_number(value):
        """Format numbers with commas for thousands"""
        try:
            if value is None:
                return "0"
            return "{:,}".format(int(value))
        except (ValueError, TypeError):
            return str(value)

    # Context processors
    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow()}

    @app.context_processor
    def inject_sidebar_ads():
        """Inject sidebar ads into templates"""
        from app.models import AdContent
        try:
            sidebar_ads = AdContent.query.filter(
            AdContent.is_active == True,
            AdContent.placement == 'sidebar',
            (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
            ).order_by(AdContent.created_at.desc()).limit(3).all()

            # Update impressions
            for ad in sidebar_ads:
                ad.impressions += 1
            db.session.commit()

            return dict(sidebar_ads=sidebar_ads)
        except Exception as e:
            logger.error(f"Error injecting sidebar ads: {str(e)}")
            return dict(sidebar_ads=[])

    @app.context_processor
    def inject_header_ads():
        """Inject header ads into templates"""
        from app.models import AdContent
        try:
            header_ads = AdContent.query.filter(
            AdContent.is_active == True,
            AdContent.placement == 'header',
            (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
            ).order_by(AdContent.created_at.desc()).limit(1).first()

            if header_ads:
                header_ads.impressions += 1
                db.session.commit()

            return dict(header_ad=header_ads)
        except Exception as e:
            logger.error(f"Error injecting header ads: {str(e)}")
            return dict(header_ad=None)

    @app.context_processor
    def inject_footer_ads():
        """Inject footer ads into templates"""
        from app.models import AdContent
        try:
            footer_ads = AdContent.query.filter(
            AdContent.is_active == True,
            AdContent.placement == 'footer',
            (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
            ).order_by(AdContent.created_at.desc()).limit(2).all()

            # Update impressions
            for ad in footer_ads:
                ad.impressions += 1
                db.session.commit()

            return dict(footer_ads=footer_ads)
        except Exception as e:
            logger.error(f"Error injecting footer ads: {str(e)}")
            return dict(footer_ads=[])

    # Add a custom filter for inline ads processing
    import re

    @app.template_filter('process_inline_ads')
    def process_inline_ads_filter(content):
        """Process inline ad shortcodes in content"""
        try:
            from app.models import AdContent

            def replace_ad_shortcode(match):
                ad_id = int(match.group(1))
                try:
                    ad = AdContent.query.filter(
                    AdContent.id == ad_id,
                    AdContent.is_active == True,
                    AdContent.placement == 'inline',
                    (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
                    ).first()

                    if ad:
                        # Update impressions
                        ad.impressions += 1
                        db.session.commit()
  
                        return f'''
                    <div class="inline-ad-container my-4 p-3 border rounded bg-light position-relative">
                        <span class="badge bg-warning position-absolute top-0 start-0 m-2">Sponsored</span>
                        <div class="inline-ad-content">
                            {ad.content}
                        </div>
                        <div class="text-end mt-2">
                            <a href="{{% if current_user.is_authenticated %}}{{{{ url_for('admin.track_ad_click', ad_id={ad.id}) }}}}{{% else %}}{{{{ url_for('main.track_ad_click', ad_id={ad.id}) }}}}{{% endif %}}"
                               target="_blank"
                               class="btn btn-sm btn-outline-primary">
                                Learn More
                            </a>
                        </div>
                    </div>
                    '''
                except Exception as e:
                    logger.error(f"Error processing inline ad {ad_id}: {str(e)}")

                return ''  # Return empty string if ad not found or error

            # Replace [ad id=X] shortcodes
            pattern = r'\[ad id=(\d+)\]'
            content = re.sub(pattern, replace_ad_shortcode, content)

            return content

        except Exception as e:
            logger.error(f"Error in inline ads filter: {str(e)}")
            return content

    @app.context_processor
    def inject_categories():
        categories = Category.query.filter_by(parent_id=None).order_by(Category.name).all()
        category_structure = []
        for cat in categories:
            subcats = Category.query.filter_by(parent_id=cat.id).order_by(Category.name).all()
            category_structure.append({'category': cat, 'subcategories': subcats})
        return dict(category_structure=category_structure)

    @app.context_processor
    def inject_ads():
        """Inject active ads into all templates"""
        from app.models import AdContent
        try:
            # Get active sidebar ads that haven't expired
            ads = AdContent.query.filter(
                AdContent.is_active == True,
                AdContent.placement == 'sidebar',
                (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
            ).order_by(AdContent.created_at.desc()).limit(3).all()
            
            # Update impressions for each ad
            for ad in ads:
                ad.impressions += 1
            db.session.commit()
            
            return dict(ads=ads)
        except Exception as e:
            logger.error(f"Error injecting ads: {str(e)}")
            return dict(ads=[])

    # CLI Commands
    @app.cli.command("generate-api-key")
    @with_appcontext
    def generate_api_key():
        """Generate an API key for a user"""
        from app.models import User, ApiKey
        import secrets

        username = input("Username: ").strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"User '{username}' not found.")
            return
            
        permissions = input("Permissions (comma-separated, default: post:create): ").strip()
        if not permissions:
            permissions = "post:create"
            
        api_key = secrets.token_urlsafe(32)
        key_record = ApiKey(
            key=api_key,
            user_id=user.id,
            permissions=permissions
        )
        db.session.add(key_record)
        db.session.commit()

        print(f"API Key for {username}: {api_key}")
        print(f"Permissions: {permissions}")
        print("Keep this key secure as it cannot be retrieved again!")

    @app.cli.command("create-admin")
    @with_appcontext
    def create_admin():
        """Create a new admin user with proper validation"""
        from app.models import User
        
        print("=== Create a New Admin User ===")

        while True:
            username = input("Username: ").strip()
            if username:
                if User.query.filter_by(username=username).first():
                    print("Username already exists. Please choose a different one.")
                else:
                    break
            else:
                print("Username cannot be empty.")

        while True:
            email = input("Email: ").strip()
            if email:
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

    @app.cli.command("init-db")
    @with_appcontext
    def init_db():
        """Initialize the database with default categories"""
        from app.models import Category
        
        default_categories = [
            'Technology', 'Science', 'Art', 'Sports', 'Entertainment',
            'News', 'Education', 'Health', 'Travel', 'Food'
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
            print(f"ID: {user.id} | Username: {user.username} | Email: {user.email} | Admin: {admin_status}")

    @app.cli.command("start-redis")
    @with_appcontext
    def start_redis():
        """Manually start Redis server for Termux"""
        if setup_redis():
            print("✅ Redis server started successfully")
        else:
            print("❌ Failed to start Redis server")

    return app
