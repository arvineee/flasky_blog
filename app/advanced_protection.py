import re
import time
import random
import logging
import hashlib
import asyncio
import aiohttp
import json
import threading
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple, Optional, Any, Set

from flask import Blueprint, request, jsonify, make_response, redirect, url_for, render_template, flash, current_app
import redis
from redis.connection import ConnectionPool
import geoip2.database
from flask_login import current_user, login_required
import diskcache as dc
import psutil
import os
import ipaddress

# Configure logging
logger = logging.getLogger(__name__)

# Create cache directory
cache_dir = os.path.expanduser("~/security_cache")
os.makedirs(cache_dir, exist_ok=True)

# Create blueprint for advanced protection
advanced_protection_bp = Blueprint('advanced_protection', __name__, 
                                  template_folder='templates',
                                  static_folder='static',
                                  url_prefix='/advanced-protection')

class AdvancedProtection:
    def __init__(self, app=None):
        self.app = app
        self.redis_client = None
        self.redis_pool = None
        self.geoip_reader = None
        self.cache = dc.Cache(cache_dir)
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.request_tracker = {}
        
        # Enhanced configuration - MORE LENIENT
        self.config = {
            'MODE': 'active',
            'REQUEST_LIMIT': 500,  # Increased from 100
            'WINDOW_SIZE': 60,
            'BAN_TIME': 300,
            'AUTO_BAN': True,
            'WAF_ENABLED': True,
            'GEO_BLOCKING_ENABLED': True,
            'JS_CHALLENGE_ENABLED': True,
            'BEHAVIORAL_ANALYSIS_ENABLED': True,
            'CAPTCHA_ENABLED': True,
            'API_RATE_LIMITING_ENABLED': True,
            'MAX_REQUEST_RATE': 1000,
            'SYN_FLOOD_THRESHOLD': 500,  # Increased from 100
            'SYN_FLOOD_WINDOW': 1,
            'SYN_BAN_DURATION': 300,
            'BASE_RATE_LIMITS': {
                '/login': {'requests': 20, 'window': 60},  # Increased from 5
                '/api/search': {'requests': 30, 'window': 30},  # Increased from 10
                '/contact': {'requests': 10, 'window': 300},  # Increased from 3
                '/register': {'requests': 5, 'window': 3600},  # Increased from 2
                'global': {'requests': 500, 'window': 60}  # Increased from 100
            }
        }
        
        # Enhanced environment configuration - MORE LENIENT
        self.environment_config = {
            'development': {
                'REQUEST_LIMIT': 2000,  # Increased
                'WINDOW_SIZE': 60,
                'AUTO_BAN': False,
                'JS_CHALLENGE_ENABLED': False,
                'SYN_FLOOD_THRESHOLD': 1000  # Increased
            },
            'production': {
                'REQUEST_LIMIT': 500,  # Increased
                'WINDOW_SIZE': 60,
                'AUTO_BAN': True,
                'JS_CHALLENGE_ENABLED': True,
                'SYN_FLOOD_THRESHOLD': 500  # Increased
            },
            'under_attack': {
                'REQUEST_LIMIT': 100,  # Increased from 10
                'WINDOW_SIZE': 60,
                'AUTO_BAN': True,
                'JS_CHALLENGE_ENABLED': True,
                'CAPTCHA_ENABLED': True,
                'SYN_FLOOD_THRESHOLD': 200  # Increased from 50
            }
        }
        
        # Enhanced storage with automatic cleanup
        self.request_counts = {}
        self.banned_ips = {}
        self.syn_banned_ips = {}
        self.ip_reputation = {}
        self.captcha_required = {}
        self.api_keys = {}
        self.challenge_data = {}
        self.security_events = []
        
        # Enhanced WAF patterns
        self.suspicious_patterns = [
            r'(?:union|select|insert|delete|drop|update|exec).*from',
            r'<script.*>.*</script>',
            r'(?:\.\./)+',
            r'\/etc\/passwd',
            r'(?:\b|\W)(?:sleep|benchmark)\(.*\)',
            r'(?:cmd\.exe|bash|powershell)',
            r'(?:php://|zlib://)',
            r'(?:xss|csrf)',
            r'(?:document\.cookie|localStorage)',
            r'(?:eval\(|function\(\))'
        ]
        
        # Enhanced geographic blocking
        self.blocked_countries = set()
        self.allowed_countries = set(['US', 'CA', 'GB', 'AU', 'DE', 'FR'])
        
        # Enhanced rate limiting
        self.endpoint_limits = self.config['BASE_RATE_LIMITS'].copy()
        self.api_rate_limits = {'default': 1000, 'premium': 10000}
        
        # Whitelisted IP ranges (localhost, private networks)
        self.whitelisted_ranges = [
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('::1/128')
        ]
        
        # External services
        self.abuseipdb_key = None
        self.cloudflare_api_key = None
        self.recaptcha_secret = None
        
        # Monitoring
        self.monitoring_active = True
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'banned_ips': 0,
            'challenges_served': 0
        }
        
        self._start_time = time.time()
        
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the protection system with the Flask app"""
        self.app = app
        
        # Load configuration
        for key in self.config:
            if key in app.config:
                self.config[key] = app.config[key]
        
        # Load external service keys
        self.abuseipdb_key = app.config.get('ABUSEIPDB_API_KEY')
        self.cloudflare_api_key = app.config.get('CLOUDFLARE_API_KEY')
        self.recaptcha_secret = app.config.get('RECAPTCHA_SECRET_KEY')
        
        # Initialize Redis
        redis_url = app.config.get('REDIS_URL')
        if redis_url:
            try:
                self.redis_pool = ConnectionPool.from_url(redis_url, max_connections=50)
                self.redis_client = redis.Redis(connection_pool=self.redis_pool)
                self.redis_client.ping()
                logger.info("Redis connected successfully")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self.redis_client = None

        # Initialize GeoIP
        geoip_path = app.config.get('GEOIP_DATABASE_PATH')
        if geoip_path and os.path.exists(geoip_path):
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_path)
                logger.info("GeoIP database loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")

        # Set environment mode
        env_mode = app.config.get('ENV', 'production')
        self.set_environment_mode(env_mode)
        
        # Register middleware and routes
        @app.before_request
        def protection_middleware():
            return self.process_request()

        self.init_protection_routes()
        app.register_blueprint(advanced_protection_bp)
        
        # Start enhanced monitoring
        self.start_enhanced_monitoring()
        logger.info("Advanced Protection System initialized")

    def format_timestamp(self, timestamp):
        """Format timestamp for display"""
        if not timestamp:
            return "Auto-expire"
        try:
            from datetime import datetime
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return str(timestamp)

    def start_enhanced_monitoring(self):
        """Start comprehensive background monitoring"""
        def monitor_loop():
            while self.monitoring_active:
                try:
                    self.monitor_traffic_patterns()
                    self.cleanup_expired_data()
                    self.adjust_protection_levels()
                    time.sleep(10)
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(30)

        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("Enhanced monitoring started")

    def cleanup_expired_data(self):
        """Clean up expired data from memory storage"""
        current_time = time.time()
        
        # Clean expired bans
        for ip in list(self.banned_ips.keys()):
            if self.banned_ips[ip]['expires'] <= current_time:
                del self.banned_ips[ip]
                logger.info(f"Auto-unbanned IP {ip}")

        # Clean expired SYN bans
        for ip in list(self.syn_banned_ips.keys()):
            if self.syn_banned_ips[ip]['expires'] <= current_time:
                del self.syn_banned_ips[ip]
                logger.info(f"Auto-unbanned IP {ip} from SYN flood ban")

        # Clean expired reputation data
        for ip in list(self.ip_reputation.keys()):
            if self.ip_reputation[ip]['expires'] <= current_time:
                del self.ip_reputation[ip]

        # Clean old request counts
        cutoff_time = current_time - 3600
        for key in list(self.request_counts.keys()):
            if self.request_counts[key]['timestamp'] < cutoff_time:
                del self.request_counts[key]

        # Clean old security events (keep only last 1000 events)
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]

    def is_whitelisted_ip(self, ip_address: str) -> bool:
        """Check if IP should be whitelisted"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for network in self.whitelisted_ranges:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False

    def apply_load_shedding(self) -> bool:
        """Apply load shedding based on system load - MUCH LESS AGGRESSIVE"""
        system_load = self.get_system_load()

        # Only apply load shedding under extreme conditions
        if system_load > 0.98:  # Only at 98%+ load
            # Only block 10% of requests at extreme load
            return random.random() > 0.1
        elif system_load > 0.95:  # At 95%+ load
            # Only block 5% of requests
            return random.random() > 0.05
        elif system_load > 0.9:  # At 90%+ load
            # Only block 2% of requests
            return random.random() > 0.02
        return True  # Allow all requests under normal load

    def init_protection_routes(self):
        """Initialize all protection routes"""
        
        @advanced_protection_bp.route('/verify-challenge', methods=['POST'])
        def verify_challenge():
            client_ip = request.remote_addr
            challenge_id = request.form.get('challenge_id')
            answer = request.form.get('answer')
            
            if self.verify_challenge(challenge_id, answer):
                self.mark_challenge_passed(client_ip)
                next_url = request.args.get('next', url_for('main.index'))
                return redirect(next_url)
            else:
                self.record_malicious_activity(client_ip, "Failed challenge attempt")
                flash("Challenge verification failed. Please try again.", "danger")
                return redirect(url_for('advanced_protection.security_challenge'))

        @advanced_protection_bp.route('/security-challenge')
        def security_challenge():
            client_ip = request.remote_addr
            challenge_data = self.generate_js_challenge(client_ip)
            return render_template('advanced_protection/challenge.html', 
                                 challenge_data=challenge_data)

        @advanced_protection_bp.route('/captcha-verification')
        def captcha_verification():
            client_ip = request.remote_addr
            captcha_data = self.generate_captcha_challenge(client_ip)
            return render_template('advanced_protection/captcha.html',
                                 captcha_data=captcha_data)

        @advanced_protection_bp.route('/verify-captcha', methods=['POST'])
        def verify_captcha():
            client_ip = request.remote_addr
            captcha_response = request.form.get('captcha_response')
            challenge_id = request.form.get('challenge_id')
            
            if self.verify_captcha(challenge_id, captcha_response):
                self.mark_challenge_passed(client_ip)
                return redirect(request.args.get('next', url_for('main.index')))
            else:
                self.record_malicious_activity(client_ip, "Failed CAPTCHA attempt")
                flash("CAPTCHA verification failed. Please try again.", "danger")
                return redirect(url_for('advanced_protection.captcha_verification'))

        @advanced_protection_bp.route('/admin/dashboard')
        @self.admin_required
        def dashboard():
            stats = self.get_comprehensive_stats()
            banned_ips = self.get_banned_ips_details()
            syn_banned_ips = self.get_syn_banned_ips()


            self.config.setdefault('CAPTCHA_ENABLED', True)
            self.config.setdefault('BEHAVIORAL_ANALYSIS_ENABLED', True)
            
            countries_list = [
                ('US', 'United States'), ('CA', 'Canada'), ('GB', 'United Kingdom'),
                ('AU', 'Australia'), ('DE', 'Germany'), ('FR', 'France'), ('IT', 'Italy'),
                ('ES', 'Spain'), ('NL', 'Netherlands'), ('SE', 'Sweden'), ('NO', 'Norway'),
                ('DK', 'Denmark'), ('FI', 'Finland'), ('RU', 'Russia'), ('CN', 'China'),
                ('JP', 'Japan'), ('KR', 'South Korea'), ('IN', 'India'), ('BR', 'Brazil'),
                ('MX', 'Mexico'), ('ZA', 'South Africa'), ('EG', 'Egypt'), ('NG', 'Nigeria'),
                ('KE', 'Kenya')
            ]
            
            return render_template('advanced_protection/dashboard.html',
                                 stats=stats,
                                 config=self.config,
                                 banned_ips=banned_ips,
                                 syn_banned_ips=syn_banned_ips,
                                 countries_list=countries_list,
                                 allowed_countries=self.allowed_countries,
                                 blocked_countries=self.blocked_countries)

        # In the update_config route, fix the checkbox handling
        @advanced_protection_bp.route('/admin/update-config', methods=['POST'])
        @self.admin_required
        def update_config():
            try:
                # Get checkbox values properly (they're 'on' when checked, absent when not)
                waf_enabled = 'waf_enabled' in request.form
                js_challenge_enabled = 'js_challenge_enabled' in request.form
                captcha_enabled = 'captcha_enabled' in request.form
                auto_ban = 'auto_ban' in request.form

                self.config.update({
                    'MODE': request.form.get('protection_mode', 'active'),
                    'REQUEST_LIMIT': int(request.form.get('request_limit', 100)),
                    'WINDOW_SIZE': int(request.form.get('window_size', 60)),
                    'BAN_TIME': int(request.form.get('ban_time', 300)),
                    'AUTO_BAN': auto_ban,
                    'WAF_ENABLED': waf_enabled,
                    'JS_CHALLENGE_ENABLED': js_challenge_enabled,
                    'CAPTCHA_ENABLED': captcha_enabled,
                    'SYN_FLOOD_THRESHOLD': int(request.form.get('syn_flood_threshold', 100))
                    })
                flash('Configuration updated successfully!', 'success')
            except Exception as e:
                flash(f'Error updating configuration: {str(e)}', 'danger')

            return redirect(url_for('advanced_protection.dashboard'))

        @advanced_protection_bp.route('/admin/unban-ip/<ip>', methods=['POST'])
        @self.admin_required
        def unban_ip_route(ip):
            self.unban_ip(ip)
            flash(f'IP {ip} has been unbanned successfully!', 'success')
            return redirect(url_for('advanced_protection.dashboard'))

        @advanced_protection_bp.route('/admin/unban-syn-ip/<ip>', methods=['POST'])
        @self.admin_required
        def unban_syn_ip_route(ip):
            self.unban_syn_ip(ip)
            flash(f'IP {ip} has been unbanned from SYN flood protection!', 'success')
            return redirect(url_for('advanced_protection.dashboard'))

        # New routes for quick actions
        @advanced_protection_bp.route('/admin/clear-challenges', methods=['POST'])
        @self.admin_required
        def clear_challenges():
            try:
                if self.redis_client:
                    challenge_keys = self.redis_client.keys('challenge:*')
                    captcha_keys = self.redis_client.keys('captcha:*')
                    for key in challenge_keys + captcha_keys:
                        self.redis_client.delete(key)
                
                self.challenge_data.clear()
                flash('All challenges cleared successfully!', 'success')
            except Exception as e:
                flash(f'Error clearing challenges: {str(e)}', 'danger')
            return redirect(url_for('advanced_protection.dashboard'))

        @advanced_protection_bp.route('/admin/flush-cache', methods=['POST'])
        @self.admin_required
        def flush_cache():
            try:
                if self.redis_client:
                    self.redis_client.flushdb()
                
                self.request_counts.clear()
                self.ip_reputation.clear()
                self.cache.clear()
                flash('Cache flushed successfully!', 'success')
            except Exception as e:
                flash(f'Error flushing cache: {str(e)}', 'danger')
            return redirect(url_for('advanced_protection.dashboard'))

        @advanced_protection_bp.route('/admin/unban-all', methods=['POST'])
        @self.admin_required
        def unban_all_ips():
            try:
                for ip in list(self.banned_ips.keys()):
                    self.unban_ip(ip)
                
                for ip in list(self.syn_banned_ips.keys()):
                    self.unban_syn_ip(ip)
                
                if self.redis_client:
                    ban_keys = self.redis_client.keys('ban:*')
                    syn_ban_keys = self.redis_client.keys('syn_ban:*')
                    for key in ban_keys + syn_ban_keys:
                        self.redis_client.delete(key)
                
                flash('All IPs unbanned successfully!', 'success')
            except Exception as e:
                flash(f'Error unbanning IPs: {str(e)}', 'danger')
            return redirect(url_for('advanced_protection.dashboard'))

        @advanced_protection_bp.route('/admin/update-countries', methods=['POST'])
        @self.admin_required
        def update_countries():
            try:
                # Get the list of allowed and blocked countries from the form
                allowed_countries = request.form.getlist('allowed_countries')
                blocked_countries = request.form.getlist('blocked_countries')

                # Update the sets in the protection system
                self.allowed_countries = set(allowed_countries)
                self.blocked_countries = set(blocked_countries)

                flash('Country settings updated successfully!', 'success')
            except Exception as e:
                flash(f'Error updating country settings: {str(e)}', 'danger')

            return redirect(url_for('advanced_protection.dashboard'))

        @advanced_protection_bp.route('/admin/set-mode/<mode>', methods=['POST'])
        @self.admin_required
        def set_protection_mode(mode):
            try:
                if mode in ['active', 'monitor', 'under_attack']:
                    self.set_environment_mode(mode)
                    flash(f'Protection mode set to {mode}!', 'success')
                else:
                    flash('Invalid protection mode!', 'danger')
            except Exception as e:
                flash(f'Error setting protection mode: {str(e)}', 'danger')
            return redirect(url_for('advanced_protection.dashboard'))

        @advanced_protection_bp.route('/admin/export-logs', methods=['GET'])
        @self.admin_required
        def export_logs():
            try:
                stats = self.get_comprehensive_stats()
                logs_data = {
                    'export_time': datetime.utcnow().isoformat(),
                    'statistics': stats,
                    'banned_ips': self.get_banned_ips_details(),
                    'recent_events': self.get_recent_security_events()
                }
                
                response = make_response(json.dumps(logs_data, indent=2))
                response.headers['Content-Type'] = 'application/json'
                response.headers['Content-Disposition'] = 'attachment; filename=security_logs.json'
                return response
            except Exception as e:
                flash(f'Error exporting logs: {str(e)}', 'danger')
                return redirect(url_for('advanced_protection.dashboard'))

    def set_environment_mode(self, mode):
        """Set protection mode based on environment"""
        if mode in self.environment_config:
            self.config.update(self.environment_config[mode])
            logger.info(f"Protection mode set to: {mode}")

    def admin_required(self, f):
        """Decorator to require admin access"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
                flash("Administrator access required.", "danger")
                return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return decorated_function

    def process_request(self):
        """Enhanced request processing pipeline - LESS AGGRESSIVE"""
        if self.should_skip_protection():
            return None

        client_ip = request.remote_addr
        self.stats['total_requests'] += 1

        # Whitelist local/private IPs
        if self.is_whitelisted_ip(client_ip):
            return None

        # Ensure start_time is set for traffic logging
        from flask import g
        if not hasattr(g, 'start_time'):
            from datetime import datetime
            g.start_time = datetime.utcnow()

        # Load shedding - MUCH LESS AGGRESSIVE
        if not self.apply_load_shedding():
            self.stats['blocked_requests'] += 1
            return self.block_response(client_ip, "Server under heavy load")

        # IP ban check (including SYN flood bans) - Add grace period
        if self.is_ip_banned(client_ip):
            # Allow a few requests even if banned (for challenge completion)
            ban_key = f"grace:{client_ip}"
            grace_count = 0
            
            if self.redis_client:
                grace_count = self.redis_client.incr(ban_key)
                self.redis_client.expire(ban_key, 30)  # 30 second grace period
            else:
                if not hasattr(self, 'grace_periods'):
                    self.grace_periods = {}
                grace_count = self.grace_periods.get(client_ip, 0) + 1
                self.grace_periods[client_ip] = grace_count
            
            if grace_count > 3:  # Allow up to 3 requests during ban period
                self.stats['blocked_requests'] += 1
                return self.block_response(client_ip, "IP address banned")

        # SYN flood protection - LESS SENSITIVE
        if not self.syn_flood_protection(client_ip):
            self.stats['blocked_requests'] += 1
            return self.block_response(client_ip, "SYN flood protection activated")

        # Enhanced security checks - WITH BACKOFF
        security_result = self.perform_security_checks(client_ip)
        if security_result:
            return security_result

        return None

    def should_skip_protection(self):
        """Check if request should skip protection - EXPANDED"""
        skip_paths = [
            '/static/', '/advanced-protection/', '/health',
            '/login', '/register', '/logout', 
            '/reset_password', '/contact',
            '/api/auth/', '/admin/login'
        ]
        
        skip_endpoints = [
            'static', 'advanced_protection.verify_challenge',
            'advanced_protection.security_challenge',
            'advanced_protection.captcha_verification',
            'advanced_protection.verify_captcha',
            'main.login', 'main.register', 'main.logout',
            'main.reset_password_request', 'main.reset_password'
        ]

        if any(request.path.startswith(path) for path in skip_paths):
            return True

        if request.endpoint in skip_endpoints:
            return True

        # Skip for authenticated admin users on admin routes
        if (hasattr(request, 'endpoint') and request.endpoint and 
            'admin' in request.endpoint and 
            hasattr(current_user, 'is_authenticated') and 
            current_user.is_authenticated and 
            getattr(current_user, 'is_admin', False)):
            return True

        return False

    def perform_security_checks(self, client_ip):
        """Perform comprehensive security checks"""
        checks = [
            (self.check_waf, "WAF rule violation"),
            (self.check_geo_blocking, "Geographic blocking violation"),
            (self.check_rate_limits, "Rate limit exceeded"),
            (self.check_behavioral, "Suspicious behavior detected"),
            (self.check_api_limits, "API limit exceeded")
        ]

        for check_func, violation_msg in checks:
            result = check_func(client_ip)
            if not result['allowed']:
                self.record_malicious_activity(client_ip, violation_msg)
                
                if result.get('challenge_required'):
                    return self.challenge_response(client_ip, result['challenge_type'])
                
                if self.should_auto_ban(client_ip):
                    self.ban_ip(client_ip, self.config['BAN_TIME'], violation_msg)
                
                return self.block_response(client_ip, violation_msg)

        return None

    # Enhanced SYN Flood Protection
    def syn_flood_protection(self, ip_address: str) -> bool:
        """Enhanced SYN flood protection with automatic unbanning"""
        if self._is_ip_syn_banned(ip_address):
            return False

        syn_key = f"syn_flood:{ip_address}"
        current_time = time.time()

        try:
            if self.redis_client:
                pipeline = self.redis_client.pipeline()
                pipeline.incr(syn_key)
                pipeline.expire(syn_key, self.config['SYN_FLOOD_WINDOW'])
                results = pipeline.execute()
                syn_count = results[0]

                if syn_count > self.config['SYN_FLOOD_THRESHOLD']:
                    self._ban_ip_syn_flood(ip_address)
                    return False
            else:
                if syn_key not in self.request_counts:
                    self.request_counts[syn_key] = {
                        'count': 0,
                        'window_start': current_time,
                        'timestamp': current_time
                    }

                syn_data = self.request_counts[syn_key]
                
                if current_time - syn_data['window_start'] > self.config['SYN_FLOOD_WINDOW']:
                    syn_data['count'] = 0
                    syn_data['window_start'] = current_time

                syn_data['count'] += 1
                syn_data['timestamp'] = current_time

                if syn_data['count'] > self.config['SYN_FLOOD_THRESHOLD']:
                    self._ban_ip_syn_flood(ip_address)
                    return False

        except Exception as e:
            logger.error(f"SYN flood protection error for {ip_address}: {e}")
            return True

        return True

    def _ban_ip_syn_flood(self, ip_address: str):
        """Ban IP for SYN flood with automatic expiration"""
        ban_duration = self.config['SYN_BAN_DURATION']
        ban_until = time.time() + ban_duration
        
        ban_data = {
            'reason': 'SYN flood detected',
            'banned_at': time.time(),
            'expires': ban_until,
            'type': 'syn_flood'
        }

        if self.redis_client:
            try:
                ban_key = f"syn_ban:{ip_address}"
                self.redis_client.setex(ban_key, ban_duration, json.dumps(ban_data))
            except Exception as e:
                logger.error(f"Redis ban error for {ip_address}: {e}")
                self.syn_banned_ips[ip_address] = ban_data
        else:
            self.syn_banned_ips[ip_address] = ban_data

        logger.warning(f"IP {ip_address} banned for SYN flood for {ban_duration} seconds")

    def _is_ip_syn_banned(self, ip_address: str) -> bool:
        """Check if IP is banned for SYN flood"""
        if self.redis_client:
            try:
                ban_key = f"syn_ban:{ip_address}"
                banned = self.redis_client.exists(ban_key)
                return banned > 0
            except Exception as e:
                logger.error(f"Redis ban check error for {ip_address}: {e}")
                pass

        if ip_address in self.syn_banned_ips:
            ban_data = self.syn_banned_ips[ip_address]
            if time.time() < ban_data['expires']:
                return True
            else:
                del self.syn_banned_ips[ip_address]

        return False

    def unban_syn_ip(self, ip_address: str):
        """Remove SYN flood ban for IP"""
        if self.redis_client:
            try:
                ban_key = f"syn_ban:{ip_address}"
                self.redis_client.delete(ban_key)
            except Exception as e:
                logger.error(f"Redis unban error for {ip_address}: {e}")

        if ip_address in self.syn_banned_ips:
            del self.syn_banned_ips[ip_address]

        logger.info(f"IP {ip_address} unbanned from SYN flood protection")

    

    # Enhanced IP Banning System
    def ban_ip(self, ip_address: str, ban_time: int = 300, reason: str = "Violation"):
        """Ban IP with automatic expiration"""
        ban_until = time.time() + ban_time
        ban_data = {
            'reason': reason,
            'banned_at': time.time(),
            'expires': ban_until,
            'type': 'manual'
        }

        if self.redis_client:
            try:
                ban_key = f"ban:{ip_address}"
                self.redis_client.setex(ban_key, ban_time, json.dumps(ban_data))
            except Exception as e:
                logger.error(f"Redis ban error for {ip_address}: {e}")
                self.banned_ips[ip_address] = ban_data
        else:
            self.banned_ips[ip_address] = ban_data

        logger.warning(f"IP {ip_address} banned until {datetime.fromtimestamp(ban_until)}. Reason: {reason}")

    def is_ip_banned(self, ip_address: str) -> bool:
        """Check if IP is banned (includes both regular and SYN bans)"""
        if self.redis_client:
            try:
                ban_key = f"ban:{ip_address}"
                if self.redis_client.exists(ban_key):
                    return True
            except Exception as e:
                logger.error(f"Redis ban check error for {ip_address}: {e}")

        if ip_address in self.banned_ips:
            ban_data = self.banned_ips[ip_address]
            if time.time() < ban_data['expires']:
                return True
            else:
                del self.banned_ips[ip_address]

        return self._is_ip_syn_banned(ip_address)

    def unban_ip(self, ip_address: str):
        """Remove IP ban"""
        if self.redis_client:
            try:
                ban_key = f"ban:{ip_address}"
                self.redis_client.delete(ban_key)
            except Exception as e:
                logger.error(f"Redis unban error for {ip_address}: {e}")

        if ip_address in self.banned_ips:
            del self.banned_ips[ip_address]

        self.unban_syn_ip(ip_address)

        logger.info(f"IP {ip_address} completely unbanned")

    def get_banned_ips_details(self):
        """Get detailed information about banned IPs with formatted dates"""
        banned_ips = {}    

        if self.redis_client:
            try:
                ban_keys = self.redis_client.keys("ban:*")
                for key in ban_keys:
                    ip = key.decode().replace('ban:', '')
                    ban_data = json.loads(self.redis_client.get(key))
                    # Format the expires timestamp
                    if 'expires' in ban_data:
                        ban_data['expires_formatted'] = self.format_timestamp(ban_data['expires'])
                    banned_ips[ip] = ban_data
            except Exception as e:
                logger.error(f"Error getting banned IPs from Redis: {e}")

        # Add memory-based bans with formatted dates
        for ip, ban_data in self.banned_ips.items():
            if time.time() < ban_data['expires']:
                ban_data['expires_formatted'] = self.format_timestamp(ban_data['expires'])
                banned_ips[ip] = ban_data

        return banned_ips

    def get_syn_banned_ips(self):
        """Get all currently SYN-banned IPs with formatted dates"""
        syn_banned = {}

        if self.redis_client:
            try:
                ban_keys = self.redis_client.keys("syn_ban:*")
                for key in ban_keys:
                    ip = key.decode().replace('syn_ban:', '')
                    ban_data = json.loads(self.redis_client.get(key))
                    # Format the expires timestamp
                    if 'expires' in ban_data:
                        ban_data['expires_formatted'] = self.format_timestamp(ban_data['expires'])
                    syn_banned[ip] = ban_data
            except Exception as e:
                logger.error(f"Error getting SYN banned IPs from Redis: {e}")

        # Add memory-based bans with formatted dates
        for ip, ban_data in self.syn_banned_ips.items():
            if time.time() < ban_data['expires']:
                ban_data['expires_formatted'] = self.format_timestamp(ban_data['expires'])
            syn_banned[ip] = ban_data

        return syn_banned

    # Enhanced Security Check Methods
    def check_waf(self, client_ip: str) -> Dict[str, Any]:
        """Enhanced WAF check"""
        if not self.config['WAF_ENABLED']:
            return {'allowed': True}

        path = request.path.lower()
        query_string = request.query_string.decode().lower()
        
        for pattern in self.suspicious_patterns:
            if (re.search(pattern, path, re.IGNORECASE) or 
                re.search(pattern, query_string, re.IGNORECASE)):
                return {'allowed': False, 'challenge_required': True, 'challenge_type': 'js'}

        return {'allowed': True}

    def check_geo_blocking(self, client_ip: str) -> Dict[str, Any]:
        """Enhanced geographic blocking check"""
        if not self.config['GEO_BLOCKING_ENABLED'] or not self.geoip_reader:
            return {'allowed': True}

        try:
            response = self.geoip_reader.city(client_ip)
            country_code = response.country.iso_code

            if country_code in self.blocked_countries:
                return {'allowed': False}

            if self.allowed_countries and country_code not in self.allowed_countries:
                return {'allowed': False}

        except Exception as e:
            logger.error(f"GeoIP lookup failed for {client_ip}: {e}")

        return {'allowed': True}

    def check_rate_limits(self, client_ip: str) -> Dict[str, Any]:
        """Enhanced rate limiting check"""
        endpoint = request.path
        rate_limit_result = self.multi_level_rate_limiting(client_ip, endpoint)

        if not rate_limit_result['allowed']:
            self.update_ip_reputation(client_ip, 10)
            
            reputation = self.get_ip_reputation(client_ip)
            if reputation > 70:
                return {'allowed': False}
            elif reputation > 30:
                return {'allowed': False, 'challenge_required': True, 'challenge_type': 'captcha'}
            else:
                return {'allowed': False, 'challenge_required': True, 'challenge_type': 'js'}

        return {'allowed': True}

    def check_behavioral(self, client_ip: str) -> Dict[str, Any]:
        """Enhanced behavioral analysis"""
        if not self.config['BEHAVIORAL_ANALYSIS_ENABLED']:
            return {'allowed': True}

        user_agent = request.headers.get('User-Agent', '').lower()
        
        headless_indicators = ['headlesschrome', 'phantomjs', 'selenium', 'puppeteer']
        if any(indicator in user_agent for indicator in headless_indicators):
            self.update_ip_reputation(client_ip, 20)
            return {'allowed': False, 'challenge_required': True, 'challenge_type': 'captcha'}

        if not user_agent or 'accept' not in request.headers:
            self.update_ip_reputation(client_ip, 5)
            return {'allowed': False, 'challenge_required': True, 'challenge_type': 'js'}

        return {'allowed': True}

    def check_api_limits(self, client_ip: str) -> Dict[str, Any]:
        """Enhanced API rate limiting"""
        if not self.config['API_RATE_LIMITING_ENABLED'] or not self.is_api_request():
            return {'allowed': True}

        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key or not self.validate_api_key(api_key):
            return {'allowed': False}

        return {'allowed': True}

    # Enhanced Rate Limiting System
    def multi_level_rate_limiting(self, client_ip: str, endpoint: str) -> Dict[str, Any]:
        """Enhanced multi-level rate limiting"""
        levels = [
            self.global_rate_limit_check(client_ip),
            self.endpoint_rate_limit_check(client_ip, endpoint),
            self.adaptive_rate_limit_check(client_ip, endpoint)
        ]

        for level_result in levels:
            if not level_result['allowed']:
                return level_result

        if self.is_suspicious_request():
            strict_result = self.strict_rate_limit_check(client_ip, endpoint)
            if not strict_result['allowed']:
                return strict_result

        return {'allowed': True, 'remaining': min(r.get('remaining', 100) for r in levels)}

    def global_rate_limit_check(self, client_ip: str) -> Dict[str, Any]:
        """Global IP-based rate limiting"""
        return self.rate_limit_check(client_ip, 'global', self.config['BASE_RATE_LIMITS']['global'])

    def endpoint_rate_limit_check(self, client_ip: str, endpoint: str) -> Dict[str, Any]:
        """Endpoint-specific rate limiting"""
        limits = self.endpoint_limits.get(endpoint, self.endpoint_limits['global'])
        return self.rate_limit_check(client_ip, endpoint, limits)

    def rate_limit_check(self, client_ip: str, scope: str, limits: Dict) -> Dict[str, Any]:
        """Generic rate limit check with Redis fallback"""
        key = f"rate_limit:{client_ip}:{scope}"
        current_time = time.time()
        window = limits['window']
        max_requests = limits['requests']

        try:
            if self.redis_client:
                pipeline = self.redis_client.pipeline()
                pipeline.incr(key)
                pipeline.expire(key, window)
                results = pipeline.execute()
                current_count = results[0]

                remaining = max(0, max_requests - current_count)
                reset_time = current_time + window

                return {
                    'allowed': current_count <= max_requests,
                    'remaining': remaining,
                    'reset': reset_time
                }
            else:
                if key not in self.request_counts:
                    self.request_counts[key] = {
                        'count': 0,
                        'window_start': current_time,
                        'timestamp': current_time
                    }

                data = self.request_counts[key]
                
                if current_time - data['window_start'] > window:
                    data['count'] = 0
                    data['window_start'] = current_time

                data['count'] += 1
                data['timestamp'] = current_time

                remaining = max(0, max_requests - data['count'])
                reset_time = data['window_start'] + window

                return {
                    'allowed': data['count'] <= max_requests,
                    'remaining': remaining,
                    'reset': reset_time
                }

        except Exception as e:
            logger.error(f"Rate limit check error for {key}: {e}")
            return {'allowed': True, 'remaining': max_requests, 'reset': current_time + window}

    # Enhanced Challenge System
    def generate_js_challenge(self, client_ip: str) -> Dict[str, Any]:
        """Generate JavaScript challenge"""
        a = random.randint(1, 20)
        b = random.randint(1, 20)
        operation = random.choice(['+', '-', '*'])
        
        if operation == '+':
            answer = a + b
            question = f"{a} + {b}"
        elif operation == '-':
            answer = a - b
            question = f"{a} - {b}"
        else:
            answer = a * b
            question = f"{a} × {b}"

        challenge_id = hashlib.md5(f"{client_ip}{time.time()}".encode()).hexdigest()
        
        challenge_data = {
            'question': question,
            'answer': answer,
            'created': time.time(),
            'expires': time.time() + 300
        }

        if self.redis_client:
            try:
                self.redis_client.setex(f"challenge:{challenge_id}", 300, str(answer))
            except:
                self.challenge_data[challenge_id] = challenge_data
        else:
            self.challenge_data[challenge_id] = challenge_data

        self.stats['challenges_served'] += 1
        return {'challenge_id': challenge_id, 'question': question}

    def verify_challenge(self, challenge_id: str, answer: str) -> bool:
        """Verify challenge response"""
        try:
            if self.redis_client:
                stored_answer = self.redis_client.get(f"challenge:{challenge_id}")
                if stored_answer and stored_answer.decode() == answer:
                    self.redis_client.delete(f"challenge:{challenge_id}")
                    return True
            else:
                if challenge_id in self.challenge_data:
                    challenge = self.challenge_data[challenge_id]
                    if time.time() < challenge['expires'] and str(challenge['answer']) == answer:
                        del self.challenge_data[challenge_id]
                        return True
        except Exception as e:
            logger.error(f"Challenge verification error: {e}")

        return False

    def generate_captcha_challenge(self, client_ip: str) -> Dict[str, Any]:
        """Generate CAPTCHA challenge"""
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        captcha_text = ''.join(random.choice(chars) for _ in range(6))
        
        challenge_id = hashlib.md5(f"captcha{client_ip}{time.time()}".encode()).hexdigest()
        
        if self.redis_client:
            try:
                self.redis_client.setex(f"captcha:{challenge_id}", 300, captcha_text)
            except:
                self.challenge_data[f"captcha_{challenge_id}"] = {
                    'text': captcha_text,
                    'expires': time.time() + 300
                }
        else:
            self.challenge_data[f"captcha_{challenge_id}"] = {
                'text': captcha_text,
                'expires': time.time() + 300
            }

        return {'challenge_id': challenge_id, 'captcha_text': captcha_text}

    def verify_captcha(self, challenge_id: str, response: str) -> bool:
        """Verify CAPTCHA response"""
        try:
            if self.redis_client:
                stored_text = self.redis_client.get(f"captcha:{challenge_id}")
                if stored_text and stored_text.decode().lower() == response.lower():
                    self.redis_client.delete(f"captcha:{challenge_id}")
                    return True
            else:
                key = f"captcha_{challenge_id}"
                if key in self.challenge_data:
                    captcha = self.challenge_data[key]
                    if time.time() < captcha['expires'] and captcha['text'].lower() == response.lower():
                        del self.challenge_data[key]
                        return True
        except Exception as e:
            logger.error(f"CAPTCHA verification error: {e}")

        return False

    # Enhanced Response Methods
    def challenge_response(self, client_ip: str, challenge_type: str):
        """Generate appropriate challenge response"""
        if challenge_type == 'js' and self.config['JS_CHALLENGE_ENABLED']:
            return redirect(url_for('advanced_protection.security_challenge'))
        elif challenge_type == 'captcha' and self.config['CAPTCHA_ENABLED']:
            return redirect(url_for('advanced_protection.captcha_verification'))
        else:
            return self.block_response(client_ip, "Access challenge required")

    def block_response(self, client_ip: str, reason: str):
        """Generate block response"""
        logger.warning(f"Blocking request from {client_ip}: {reason}")
        
        if self.is_api_request():
            return jsonify({
                'error': 'Access denied',
                'reason': reason,
                'ip': client_ip,
                'timestamp': datetime.utcnow().isoformat()
            }), 429

        return render_template('advanced_protection/block.html',
                             reason=reason,
                             ip_address=client_ip), 429

    # Real Data Collection Methods
    def get_active_sessions_count(self) -> int:
        """Get real active sessions count"""
        try:
            if self.redis_client:
                session_keys = self.redis_client.keys("session:*")
                return len(session_keys)
            else:
                cutoff_time = time.time() - 1800
                active_ips = set()
                for key, data in self.request_counts.items():
                    if data.get('timestamp', 0) > cutoff_time:
                        ip = key.split(':')[1] if ':' in key else 'unknown'
                        active_ips.add(ip)
                return len(active_ips)
        except Exception as e:
            logger.error(f"Error counting active sessions: {e}")
            return 0

    def get_suspicious_patterns_count(self) -> int:
        """Get count of detected suspicious patterns"""
        try:
            cutoff_time = time.time() - 3600
            count = 0
            for ip, data in self.ip_reputation.items():
                if data.get('last_waf_trigger', 0) > cutoff_time:
                    count += 1
            return count
        except Exception as e:
            logger.error(f"Error counting suspicious patterns: {e}")
            return 0

    def get_blocks_prevented_count(self) -> int:
        """Get real count of prevented blocks"""
        return self.stats.get('blocked_requests', 0)

    def get_recent_security_events(self) -> List[Dict]:
        """Get real recent security events"""
        events = []
        current_time = time.time()
        
        # Add recent bans
        for ip, data in list(self.banned_ips.items())[:10]:
            if current_time - data.get('banned_at', 0) < 86400:
                events.append({
                    'type': 'IP Banned',
                    'time': self.format_time_ago(data.get('banned_at', current_time)),
                    'description': f"IP banned: {data.get('reason', 'Unknown')}",
                    'ip': ip
                })
        
        # Add high-risk IPs
        high_risk_ips = []
        for ip, data in self.ip_reputation.items():
            if data.get('score', 0) > 70 and current_time - data.get('updated', 0) < 3600:
                high_risk_ips.append(ip)
        
        for ip in high_risk_ips[:5]:
            events.append({
                'type': 'High Risk IP',
                'time': 'Just now',
                'description': 'High risk activity detected',
                'ip': ip
            })
        
        return events[:10]

    def get_top_threat_sources(self) -> List[Dict]:
        """Get real threat sources with geographic data"""
        threat_sources = {}
        current_time = time.time()
        
        for ip, data in self.ip_reputation.items():
            if data.get('score', 0) > 30 and current_time - data.get('updated', 0) < 86400:
                country = self.get_ip_country(ip)
                if country not in threat_sources:
                    threat_sources[country] = 0
                threat_sources[country] += 1
        
        result = []
        for country, count in sorted(threat_sources.items(), key=lambda x: x[1], reverse=True)[:10]:
            risk_level = 'high' if count > 10 else 'medium' if count > 5 else 'low'
            result.append({
                'country': country,
                'count': count,
                'risk': risk_level
            })
        
        return result

    def get_ip_country(self, ip_address: str) -> str:
        """Get country for IP address"""
        try:
            if self.geoip_reader:
                response = self.geoip_reader.city(ip_address)
                return response.country.iso_code
        except:
            pass
        return 'Unknown'

    def format_time_ago(self, timestamp: float) -> str:
        """Format timestamp as time ago"""
        seconds = time.time() - timestamp
        if seconds < 60:
            return f"{int(seconds)} seconds ago"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes ago"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours ago"
        else:
            return f"{int(seconds/86400)} days ago"

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive protection statistics with real data"""
        current_time = time.time()
        
        stats = {
            'total_requests': self.stats.get('total_requests', 0),
            'requests_blocked': self.stats.get('blocked_requests', 0),
            'currently_banned': len(self.get_banned_ips_details()),
            'syn_banned': len(self.get_syn_banned_ips()),
            'total_tracked_ips': len(self.ip_reputation),
            'system_load': self.get_system_load(),
            'memory_usage': self.get_memory_usage(),
            'uptime': current_time - self._start_time,
            'redis_connected': self.redis_client is not None,
            'geoip_available': self.geoip_reader is not None,
            'challenges_served': self.stats.get('challenges_served', 0),
            'active_challenges': len(self.challenge_data),
            'current_rps': self.get_current_rps(),
            'api_keys': len(self.api_keys),
            'waf_rules': len(self.suspicious_patterns),
            'active_sessions': self.get_active_sessions_count(),
            'high_risk_ips': len([ip for ip, rep in self.ip_reputation.items() 
                                 if rep.get('score', 0) > 70]),
            'suspicious_patterns': self.get_suspicious_patterns_count(),
            'blocks_prevented': self.get_blocks_prevented_count(),
            'recent_events': self.get_recent_security_events(),
            'top_threat_sources': self.get_top_threat_sources()
        }
        
        return stats

    def get_current_rps(self) -> int:
        """Get current requests per second"""
        try:
            current_time = time.time()
            recent_requests = 0

            for key, data in self.request_counts.items():
                if key.startswith('rate_limit:') and current_time - data.get('timestamp', 0) < 1:
                    recent_requests += 1

            return min(recent_requests, 1000)
        except:
            return 0

    def monitor_traffic_patterns(self):
        """Monitor traffic patterns for automatic adjustment"""
        try:
            current_time = time.time()
            window = 60

            if self.redis_client:
                rps_key = f"rps:{int(current_time // window)}"
                self.redis_client.incr(rps_key)
                self.redis_client.expire(rps_key, window * 2)

            current_rps = self.get_current_rps()
            if current_rps > 500:
                self.set_environment_mode('under_attack')
            elif current_rps > 100:
                self.set_environment_mode('production')
            else:
                self.set_environment_mode('development')

        except Exception as e:
            logger.error(f"Traffic monitoring error: {e}")

    def adjust_protection_levels(self):
        """Automatically adjust protection levels based on system state"""
        system_load = self.get_system_load()
        
        if system_load > 0.8:
            self.config['SYN_FLOOD_THRESHOLD'] = max(50, self.config['SYN_FLOOD_THRESHOLD'] - 10)
            self.config['REQUEST_LIMIT'] = max(10, self.config['REQUEST_LIMIT'] - 10)
        elif system_load < 0.3:
            self.config['SYN_FLOOD_THRESHOLD'] = min(200, self.config['SYN_FLOOD_THRESHOLD'] + 10)
            self.config['REQUEST_LIMIT'] = min(500, self.config['REQUEST_LIMIT'] + 10)

    # Utility Methods
    def get_system_load(self) -> float:
        """Get current system load"""
        try:
            return psutil.cpu_percent(interval=0.1) / 100.0
        except:
            return 0.0

    def get_memory_usage(self) -> float:
        """Get current memory usage"""
        try:
            return psutil.virtual_memory().percent / 100.0
        except:
            return 0.0

    def is_api_request(self) -> bool:
        """Check if request is an API request"""
        return request.path.startswith('/api/') or 'application/json' in request.headers.get('Accept', '')

    def is_suspicious_request(self) -> bool:
        """Check if request is suspicious"""
        user_agent = request.headers.get('User-Agent', '').lower()
        suspicious_ua_indicators = ['bot', 'crawler', 'spider', 'scraper']
        
        return (not user_agent or 
                any(indicator in user_agent for indicator in suspicious_ua_indicators) or
                self.get_ip_reputation(request.remote_addr) > 50)

    def should_auto_ban(self, client_ip: str) -> bool:
        """Determine if IP should be auto-banned"""
        return (self.config['AUTO_BAN'] and 
                self.get_ip_reputation(client_ip) > 70 and
                self.config['MODE'] != 'development')

    # IP Reputation System
    def update_ip_reputation(self, ip_address: str, score: int):
        """Update IP reputation score"""
        current = self.get_ip_reputation(ip_address)
        new_score = min(100, current + score)
        
        reputation_data = {
            'score': new_score,
            'updated': time.time(),
            'expires': time.time() + 86400
        }

        if self.redis_client:
            try:
                self.redis_client.setex(f"reputation:{ip_address}", 86400, new_score)
            except:
                self.ip_reputation[ip_address] = reputation_data
        else:
            self.ip_reputation[ip_address] = reputation_data

    def get_ip_reputation(self, ip_address: str) -> int:
        """Get IP reputation score"""
        try:
            if self.redis_client:
                score = self.redis_client.get(f"reputation:{ip_address}")
                return int(score) if score else 0
            else:
                if ip_address in self.ip_reputation:
                    rep_data = self.ip_reputation[ip_address]
                    if time.time() < rep_data['expires']:
                        return rep_data['score']
                    else:
                        del self.ip_reputation[ip_address]
        except Exception as e:
            logger.error(f"Reputation check error for {ip_address}: {e}")
        
        return 0

    def record_malicious_activity(self, ip_address: str, reason: str):
        """Record malicious activity"""
        self.update_ip_reputation(ip_address, 5)
        logger.warning(f"Malicious activity from {ip_address}: {reason}")

    def mark_challenge_passed(self, ip_address: str):
        """Mark that IP passed a challenge"""
        self.update_ip_reputation(ip_address, -10)
        
        if self.redis_client:
            try:
                self.redis_client.setex(f"challenge_passed:{ip_address}", 3600, "1")
            except:
                pass

    def validate_api_key(self, api_key: str) -> bool:
        """Validate API key"""
        return api_key in self.api_keys

    def adaptive_rate_limit_check(self, client_ip: str, endpoint: str) -> Dict[str, Any]:
        """Adaptive rate limiting based on system load"""
        base_limits = self.endpoint_limits.get(endpoint, self.endpoint_limits['global'])
        system_load = self.get_system_load()

        if system_load > 0.7:
            adjusted = {
                'requests': max(1, base_limits['requests'] // 2),
                'window': base_limits['window']
            }
        elif system_load > 0.4:
            adjusted = {
                'requests': max(1, int(base_limits['requests'] * 0.7)),
                'window': base_limits['window']
            }
        else:
            adjusted = base_limits

        return self.rate_limit_check(client_ip, f"adaptive:{endpoint}", adjusted)

    def strict_rate_limit_check(self, client_ip: str, endpoint: str) -> Dict[str, Any]:
        """Strict rate limiting for suspicious requests"""
        base_limits = self.endpoint_limits.get(endpoint, self.endpoint_limits['global'])
        strict_limits = {
            'requests': max(1, base_limits['requests'] // 3),
            'window': base_limits['window']
        }
        return self.rate_limit_check(client_ip, f"strict:{endpoint}", strict_limits)

    def get_system_load(self) -> float:
        """Get current system load with proper error handling"""
        try:
            # Get load average for the past 1 minute
            load_avg = os.getloadavg()[0]  # 1-minute load average
            cpu_count = os.cpu_count() or 1
            return min(load_avg / cpu_count, 1.0)  # Normalize to 0-1
        except (OSError, AttributeError):
            try:
                # Fallback to psutil
                return psutil.cpu_percent(interval=0.1) / 100.0
            except:
                return 0.0


    def get_current_rps(self) -> int:
        """Get current requests per second with real tracking"""
        try:
            current_time = time.time()
            rps_key = f"rps:{int(current_time)}"  # Track by second

            if self.redis_client:
                # Use Redis for accurate counting
                pipeline = self.redis_client.pipeline()
                pipeline.incr(rps_key)
                pipeline.expire(rps_key, 2)  # Keep for 2 seconds
                result = pipeline.execute()
                return min(result[0], 1000)
            else:
                # Memory-based tracking
                if not hasattr(self, 'request_tracker'):
                    self.request_tracker = {}

                # Clean old entries
                cutoff = current_time - 2
                for ts in list(self.request_tracker.keys()):
                    if ts < cutoff:
                        del self.request_tracker[ts]

                # Count current second
                current_second = int(current_time)
                self.request_tracker[current_second] = self.request_tracker.get(current_second, 0) + 1
                return min(self.request_tracker.get(current_second, 0), 1000)
        except Exception as e:
            logger.error(f"RPS calculation error: {e}")
            return 0


    def get_memory_usage(self) -> float:
        """Get current memory usage with proper error handling"""
        try:
            return psutil.virtual_memory().percent / 100.0
        except:
            return 0.0
    

# Global instance
advanced_protection = AdvancedProtection()

# Protection decorator
def protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function
