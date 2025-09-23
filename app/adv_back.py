import re
import time
import random
import logging
import hashlib
import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, request, jsonify, make_response, redirect, url_for, render_template, flash, current_app
import redis
from redis.connection import ConnectionPool
import geoip2.database
from flask_login import current_user
import diskcache as dc
import psutil
import os
import diskcache as dc

cache_dir = os.path.expanduser("~/security_cache")  # ~/security_cache is inside your home
os.makedirs(cache_dir, exist_ok=True)  # create it if it doesn’t exist


logger = logging.getLogger(__name__)

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
        self.config = {
            'MODE': 'active',  # monitor, active, passive
            'REQUEST_LIMIT': 100,
            'WINDOW_SIZE': 60,
            'BAN_TIME': 300,
            'AUTO_BAN': True,
            'WAF_ENABLED': True,
            'GEO_BLOCKING_ENABLED': True,
            'JS_CHALLENGE_ENABLED': True,
            'BEHAVIORAL_ANALYSIS_ENABLED': True,
            'CAPTCHA_ENABLED': True,
            'API_RATE_LIMITING_ENABLED': True,
            'MAX_REQUEST_RATE': 1000,  # Max requests per second before load shedding
            'BASE_RATE_LIMITS': {
                '/login': {'requests': 5, 'window': 60},
                '/api/search': {'requests': 10, 'window': 30},
                '/contact': {'requests': 3, 'window': 300},
                '/register': {'requests': 2, 'window': 3600},
                'global': {'requests': 100, 'window': 60}
            }
        }
        
        # Environment-specific configuration
        self.environment_config = {
            'development': {
                'REQUEST_LIMIT': 1000,
                'WINDOW_SIZE': 60,
                'AUTO_BAN': False,
                'JS_CHALLENGE_ENABLED': False
            },
            'production': {
                'REQUEST_LIMIT': 100,
                'WINDOW_SIZE': 60,
                'AUTO_BAN': True,
                'JS_CHALLENGE_ENABLED': True
            },
            'under_attack': {
                'REQUEST_LIMIT': 10,
                'WINDOW_SIZE': 60,
                'AUTO_BAN': True,
                'JS_CHALLENGE_ENABLED': True,
                'CAPTCHA_ENABLED': True
            }
        }
        
        # Initialize storage
        self.request_counts = {}
        self.banned_ips = {}
        self.ip_reputation = {}
        self.captcha_required = {}
        self.api_keys = {}
        
        # Patterns for WAF
        self.suspicious_patterns = [
            r'(?:union|select|insert|delete|drop|update|exec).*from',
            r'<script.*>.*</script>',
            r'(?:\.\./)+',  # Directory traversal
            r'\/etc\/passwd',  # File inclusion
            r'(?:\b|\W)(?:sleep|benchmark)\(.*\)',  # SQL timing attacks
        ]
        
        # Geographic blocking
        self.blocked_countries = set()
        self.allowed_countries = set(['US', 'CA', 'GB', 'AU', 'DE', 'FR'])  # Example allowed countries
        
        # Endpoint-specific limits
        self.endpoint_limits = self.config['BASE_RATE_LIMITS'].copy()
        
        # API rate limiting
        self.api_rate_limits = {
            'default': 1000,  # Requests per hour per API key
            'premium': 10000
        }
        
        # External service keys (should be set in app config)
        self.abuseipdb_key = None
        self.cloudflare_api_key = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the protection system with the Flask app"""
        self.app = app
        
        # Load configuration from app config
        for key in self.config:
            if key in app.config:
                self.config[key] = app.config[key]
        
        # Load external service keys
        self.abuseipdb_key = app.config.get('ABUSEIPDB_API_KEY')
        self.cloudflare_api_key = app.config.get('CLOUDFLARE_API_KEY')
        
        # Initialize Redis with connection pooling if configured
        redis_url = app.config.get('REDIS_URL')
        if redis_url:
            try:
                self.redis_pool = ConnectionPool.from_url(redis_url, max_connections=50)
                self.redis_client = redis.Redis(connection_pool=self.redis_pool)
                # Test the connection
                self.redis_client.ping()
                logger.info("Redis connected successfully with connection pooling")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self.redis_client = None
                self.redis_pool = None

        # Load country sets from Redis if available
        if self.redis_client:
            try:
                allowed = self.redis_client.get('allowed_countries')
                if allowed:
                    self.allowed_countries = set(json.loads(allowed))
                    blocked = self.redis_client.get('blocked_countries')
                    if blocked:
                        self.blocked_countries = set(json.loads(blocked))
            except Exception as e:
                logger.error(f"Error loading country sets from Redis: {e}")
        
        # Initialize GeoIP database if available
        geoip_path = app.config.get('GEOIP_DATABASE_PATH')
        if geoip_path:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_path)
                logger.info("GeoIP database loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")
                self.geoip_reader = None
        
        # Set environment mode
        env_mode = app.config.get('ENV', 'production')
        self.set_environment_mode(env_mode)
        
        # Register middleware
        @app.before_request
        def protection_middleware():
            return self.process_request()

        # Register protection routes                                
        self.init_protection_routes()
        
        # Register the blueprint
        app.register_blueprint(advanced_protection_bp)
        
        # Start background monitoring task
        self.start_monitoring()
    
    def start_monitoring(self):
        """Start background monitoring of traffic patterns"""
        def monitor_loop():
            while True:
                try:
                    self.monitor_traffic_patterns()
                    time.sleep(10)  # Check every 10 seconds
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(30)  # Wait longer on error
        
        # Start monitoring in a background thread
        import threading
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("Started background monitoring thread")
    
    def init_protection_routes(self):
        """Initialize routes for protection management"""
        
        @advanced_protection_bp.route('/verify-challenge', methods=['POST'])
        def verify_challenge():
            challenge_id = request.form.get('challenge_id')
            answer = request.form.get('answer')
            
            if self.verify_challenge(challenge_id, answer):
                self.mark_challenge_passed(request.remote_addr)
                next_url = request.args.get('next', url_for('main.index'))
                return redirect(next_url)
            else:
                flash("Challenge failed. Please try again.", "danger")
                return redirect(url_for('advanced_protection.security_challenge'))
        
        @advanced_protection_bp.route('/security-challenge')
        def security_challenge():
            client_ip = request.remote_addr
            return self.js_challenge_response(client_ip)
        
        @advanced_protection_bp.route('/captcha-verification')
        def captcha_verification():
            ip_address = request.args.get('ip', request.remote_addr)
            return render_template('advanced_protection/captcha.html', ip_address=ip_address)
        
        @advanced_protection_bp.route('/verify-captcha', methods=['POST'])
        def verify_captcha():
            ip_address = request.form.get('ip')
            # In a real implementation, verify the CAPTCHA response
            # For now, we'll just mark it as passed
            self.record_malicious_activity(ip_address, "CAPTCHA passed")
            return redirect(url_for('main.index'))
        
        @advanced_protection_bp.route('/admin/dashboard')
        @self.admin_required
        def dashboard():
            stats = self.get_stats()
            banned_ips = self.get_banned_ips()
            # Load country list
            countries_list = [
                    ('US', 'United States'), ('CA', 'Canada'), ('GB', 'United Kingdom'), 
                    ('AU', 'Australia'), ('DE', 'Germany'), ('FR', 'France'), ('IT', 'Italy'),
                    ('ES', 'Spain'), ('NL', 'Netherlands'), ('SE', 'Sweden'), ('NO', 'Norway'),
                    ('DK', 'Denmark'), ('FI', 'Finland'), ('RU', 'Russia'), ('CN', 'China'),
                    ('JP', 'Japan'), ('KR', 'South Korea'), ('IN', 'India'), ('BR', 'Brazil'),
                    ('MX', 'Mexico'), ('ZA', 'South Africa'), ('EG', 'Egypt'), ('NG', 'Nigeria'),('KE','KENYA'),
                    ]
            return render_template('advanced_protection/dashboard.html', 
                         stats=stats, 
                         config=self.config,
                         banned_ips=banned_ips,
                         protection_mode=self.config['MODE'],
                         countries_list=countries_list,
                         allowed_countries=self.allowed_countries,
                         blocked_countries=self.blocked_countries)
        
        @advanced_protection_bp.route('/admin/update-config', methods=['POST'])
        @self.admin_required
        def update_config():
            try:
                self.config['MODE'] = request.form.get('protection_mode', 'active')
                self.config['REQUEST_LIMIT'] = int(request.form.get('request_limit', 100))
                self.config['WINDOW_SIZE'] = int(request.form.get('window_size', 60))
                self.config['BAN_TIME'] = int(request.form.get('ban_time', 300))
                self.config['AUTO_BAN'] = request.form.get('auto_ban') == 'true'
                self.config['WAF_ENABLED'] = request.form.get('waf_enabled') == 'true'
                self.config['JS_CHALLENGE_ENABLED'] = request.form.get('js_challenge_enabled') == 'true'
                
                flash('Protection settings updated successfully!', 'success')
            except Exception as e:
                flash(f'Error updating settings: {str(e)}', 'danger')
            
            return redirect(url_for('advanced_protection.dashboard'))
        
        @advanced_protection_bp.route('/admin/update-country-access', methods=['POST'])
        @self.admin_required
        def update_country_access():
            allowed_countries = request.form.getlist('allowed_countries')
            blocked_countries = request.form.getlist('blocked_countries')
            # Update the country sets
            self.allowed_countries = set(allowed_countries)
            self.blocked_countries = set(blocked_countries)

            # Save to Redis if available
            if self.redis_client:
                try:
                    self.redis_client.set('allowed_countries', json.dumps(list(self.allowed_countries)))
                    self.redis_client.set('blocked_countries', json.dumps(list(self.blocked_countries)))
                except Exception as e:
                    logger.error(f"Error saving country sets to Redis: {e}")
                    flash('Country access settings updated successfully!', 'success')

            return redirect(url_for('advanced_protection.dashboard'))
        
        @advanced_protection_bp.route('/admin/unban/<ip>', methods=['POST'])
        @self.admin_required
        def unban_ip_route(ip):
            self.unban_ip(ip)
            flash(f'IP {ip} has been unbanned successfully!', 'success')
            return redirect(url_for('advanced_protection.dashboard'))
        
        @advanced_protection_bp.route('/admin/set-environment/<env>', methods=['POST'])
        @self.admin_required
        def set_environment_route(env):
            self.set_environment_mode(env)
            flash(f'Environment mode set to {env}', 'success')
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
            if not current_user.is_authenticated or not current_user.is_admin:
                flash("Access Denied! Admin required.", "danger")
                return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return decorated_function
    
    def process_request(self):
        """Process each incoming request through the protection system"""
        # Skip protection for static files and protection routes
        if (request.path.startswith('/static/') or 
            request.path.startswith('/advanced-protection/') or
            request.endpoint in ['static', 'advanced_protection.verify_challenge', 
                               'advanced_protection.security_challenge', 
                               'advanced_protection.captcha_verification', 
                               'advanced_protection.verify_captcha']):
            return None
        
        client_ip = request.remote_addr
        endpoint = request.path
        
        # Load shedding check
        if not self.apply_load_shedding(request):
            return self.block_response(client_ip, "Server under heavy load - request dropped")
        
        # Check if IP is banned
        if self.is_ip_banned(client_ip):
            return self.block_response(client_ip, "IP address banned")
        
        # SYN flood protection
        if not self.syn_flood_protection(client_ip):
            return self.block_response(client_ip, "SYN flood protection activated")
        
        # Request fingerprinting for anomaly detection
        if self.detect_anomalous_traffic():
            self.record_malicious_activity(client_ip, "Anomalous traffic pattern detected")
            return self.js_challenge_response(client_ip)
        
        # Web Application Firewall check
        if self.config['WAF_ENABLED'] and not self.waf_check(request):
            self.record_malicious_activity(client_ip, "WAF rule violation")
            return self.block_response(client_ip, "Request blocked by WAF")
        
        # Geographic blocking
        if self.config['GEO_BLOCKING_ENABLED'] and not self.cached_geo_check(client_ip):
            self.record_malicious_activity(client_ip, "Geographic blocking violation")
            return self.block_response(client_ip, "Request blocked by geographic policy")
        
        # Multi-level rate limiting
        rate_limit_result = self.multi_level_rate_limiting(client_ip, endpoint)
        if not rate_limit_result['allowed']:
            self.record_malicious_activity(client_ip, f"Rate limit exceeded: {endpoint}")
            
            # Auto-ban if enabled and threshold exceeded
            if self.config['AUTO_BAN'] and self.get_ip_reputation(client_ip) > 50:
                self.ban_ip(client_ip, self.config['BAN_TIME'], "Rate limit violation")
            
            # JS challenge for suspicious requests
            if self.config['JS_CHALLENGE_ENABLED'] and not self.has_passed_challenge(client_ip):
                return self.js_challenge_response(client_ip)
            
            # CAPTCHA for repeated violations
            if self.config['CAPTCHA_ENABLED'] and self.should_require_captcha(client_ip):
                return self.captcha_response(client_ip)
            
            return self.block_response(client_ip, "Rate limit exceeded")
        
        # Behavioral analysis
        if self.config['BEHAVIORAL_ANALYSIS_ENABLED'] and not self.behavioral_check(request):
            self.record_malicious_activity(client_ip, "Suspicious behavior detected")
            return self.js_challenge_response(client_ip)
        
        # API rate limiting for authenticated requests
        if self.config['API_RATE_LIMITING_ENABLED'] and self.is_api_request(request):
            api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            if api_key and not self.validate_api_key(api_key):
                return jsonify({'error': 'Invalid or rate-limited API key'}), 429
        
        # Cloudflare integration for suspicious requests
        cloudflare_response = self.integrate_with_cloudflare(client_ip)
        if cloudflare_response:
            return cloudflare_response
        
        return None
    
    def waf_check(self, request):
        """Check request against WAF rules"""
        # Use cached version for performance
        return self.cached_waf_check(request.path, request.headers.get('User-Agent', ''))
    
    @lru_cache(maxsize=10000)
    def cached_waf_check(self, request_path, user_agent):
        """Cached WAF check for common patterns"""
        cache_key = f"waf_{hash(request_path)}_{hash(user_agent)}"
        result = self.cache.get(cache_key)
        
        if result is None:
            # Perform actual WAF check
            result = self.perform_waf_check(request_path, user_agent)
            self.cache.set(cache_key, result, expire=300)  # Cache for 5 minutes
        
        return result
    
    def perform_waf_check(self, request_path, user_agent):
        """Actual WAF check implementation"""
        # Check URL path
        for pattern in self.suspicious_patterns:
            if re.search(pattern, request_path, re.IGNORECASE):
                return False
        
        # Check User-Agent
        for pattern in self.suspicious_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return False
        
        # Check POST data (if available in cache context)
        # Note: This is a simplified version - in practice, you might need to handle this differently
        return True
    
    @lru_cache(maxsize=1000)
    def cached_geo_check(self, ip_address):
        """Cached geographic check"""
        cache_key = f"geo_{ip_address}"
        result = self.cache.get(cache_key)
        
        if result is None:
            result = self.geo_check(ip_address)
            self.cache.set(cache_key, result, expire=3600)  # Cache for 1 hour
        
        return result
    
    def geo_check(self, ip_address):
        """Check if request comes from allowed country"""
        if not self.geoip_reader:
            return True  # Allow if GeoIP not configured
        
        try:
            response = self.geoip_reader.city(ip_address)
            country_code = response.country.iso_code
            
            # Check blocked countries
            if country_code in self.blocked_countries:
                return False
            
            # Check allowed countries (if any are specified)
            if self.allowed_countries and country_code not in self.allowed_countries:
                return False
            
            return True
        except:
            return True  # Allow if GeoIP lookup fails
    
    def distributed_rate_limit_check(self, ip_address, endpoint):
        """Distributed rate limiting using token bucket algorithm"""
        bucket_key = f"rate_token_bucket:{ip_address}:{endpoint}"
        limits = self.endpoint_limits.get(endpoint, self.endpoint_limits['global'])
        
        # Use Lua script for atomic operations
        lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local max_tokens = tonumber(ARGV[3])
        local token_rate = tonumber(ARGV[4])
        
        local bucket = redis.call('hmget', key, 'tokens', 'last_update')
        local tokens = tonumber(bucket[1]) or max_tokens
        local last_update = tonumber(bucket[2]) or now
        
        -- Calculate new tokens based on time passed
        local time_passed = now - last_update
        local new_tokens = math.floor(time_passed * token_rate)
        
        if new_tokens > 0 then
            tokens = math.min(tokens + new_tokens, max_tokens)
            last_update = now
        end
        
        if tokens >= 1 then
            tokens = tokens - 1
            redis.call('hmset', key, 'tokens', tokens, 'last_update', last_update)
            redis.call('expire', key, window)
            return {1, tokens}  -- allowed, remaining
        else
            return {0, 0}  -- not allowed, remaining
        end
        """
        
        try:
            result = self.redis_client.eval(lua_script, 1, bucket_key, 
                                          time.time(), limits['window'], 
                                          limits['requests'], 1/limits['window'])
            return {'allowed': bool(result[0]), 'remaining': result[1]}
        except redis.exceptions.RedisError:
            # Fallback to simpler method if Redis is unavailable
            return self.fallback_rate_limit_check(ip_address, endpoint)
    
    def fallback_rate_limit_check(self, ip_address, endpoint):
        """Fallback rate limiting when Redis is unavailable"""
        limits = self.endpoint_limits.get(endpoint, self.endpoint_limits['global'])
        key = f"{ip_address}:{endpoint}"
        now = time.time()
        
        if key in self.request_counts:
            count, timestamp = self.request_counts[key]
            
            if now - timestamp < limits['window']:
                if count >= limits['requests']:
                    return {'allowed': False, 'remaining': 0, 'reset': limits['window'] - (now - timestamp)}
                
                self.request_counts[key] = (count + 1, timestamp)
                return {'allowed': True, 'remaining': limits['requests'] - count - 1, 'reset': limits['window'] - (now - timestamp)}
            else:
                self.request_counts[key] = (1, now)
                return {'allowed': True, 'remaining': limits['requests'] - 1, 'reset': limits['window']}
        else:
            self.request_counts[key] = (1, now)
            return {'allowed': True, 'remaining': limits['requests'] - 1, 'reset': limits['window']}
    
    def multi_level_rate_limiting(self, ip_address, endpoint):
        """Implement multiple levels of rate limiting"""
        # Level 1: Global IP-based rate limiting
        global_limit = self.distributed_rate_limit_check(ip_address, 'global')
        if not global_limit['allowed']:
            return global_limit
        
        # Level 2: Endpoint-specific rate limiting
        endpoint_limit = self.distributed_rate_limit_check(ip_address, endpoint)
        if not endpoint_limit['allowed']:
            return endpoint_limit
        
        # Level 3: Adaptive rate limiting based on system load
        adaptive_limit = self.adaptive_rate_limiting(ip_address, endpoint)
        if not adaptive_limit['allowed']:
            return adaptive_limit
        
        # Level 4: Strict rate limiting for suspicious patterns
        if self.is_suspicious_request(request):
            strict_limit = self.strict_rate_limit_check(ip_address, endpoint)
            if not strict_limit['allowed']:
                return strict_limit
        
        return {'allowed': True, 'remaining': min(global_limit['remaining'], endpoint_limit['remaining'])}
    
    def adaptive_rate_limiting(self, ip_address, endpoint):
        """Dynamically adjust rate limits based on current load"""
        current_load = self.get_system_load()
        
        # Adjust limits based on system load
        base_limits = self.endpoint_limits.get(endpoint, self.endpoint_limits['global'])
        
        if current_load > 0.8:  # High load
            adjusted_limits = {
                'requests': max(1, base_limits['requests'] // 2),
                'window': base_limits['window'] * 2
            }
        elif current_load > 0.6:  # Medium load
            adjusted_limits = {
                'requests': max(1, int(base_limits['requests'] * 0.7)),
                'window': base_limits['window']
            }
        else:  # Normal load
            adjusted_limits = base_limits
        
        return self.rate_limit_check_with_limits(ip_address, endpoint, adjusted_limits)
    
    def rate_limit_check_with_limits(self, ip_address, endpoint, limits):
        """Rate limit check with custom limits"""
        if self.redis_client:
            try:
                key = f"rate_limit:{ip_address}:{endpoint}"
                current = self.redis_client.get(key)
                
                if current:
                    current = int(current)
                    if current >= limits['requests']:
                        return {'allowed': False, 'remaining': 0, 'reset': limits['window']}
                    
                    self.redis_client.incr(key, 1)
                    return {'allowed': True, 'remaining': limits['requests'] - current - 1, 'reset': limits['window']}
                else:
                    self.redis_client.setex(key, limits['window'], 1)
                    return {'allowed': True, 'remaining': limits['requests'] - 1, 'reset': limits['window']}
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory rate limiting")
                # Fall back to in-memory if Redis is unavailable
                return self.fallback_rate_limit_with_limits(ip_address, endpoint, limits)
        else:
            return self.fallback_rate_limit_with_limits(ip_address, endpoint, limits)
    
    def fallback_rate_limit_with_limits(self, ip_address, endpoint, limits):
        """Fallback rate limiting with custom limits"""
        key = f"{ip_address}:{endpoint}"
        now = time.time()
        
        if key in self.request_counts:
            count, timestamp = self.request_counts[key]
            
            if now - timestamp < limits['window']:
                if count >= limits['requests']:
                    return {'allowed': False, 'remaining': 0, 'reset': limits['window'] - (now - timestamp)}
                
                self.request_counts[key] = (count + 1, timestamp)
                return {'allowed': True, 'remaining': limits['requests'] - count - 1, 'reset': limits['window'] - (now - timestamp)}
            else:
                self.request_counts[key] = (1, now)
                return {'allowed': True, 'remaining': limits['requests'] - 1, 'reset': limits['window']}
        else:
            self.request_counts[key] = (1, now)
            return {'allowed': True, 'remaining': limits['requests'] - 1, 'reset': limits['window']}
    
    def strict_rate_limit_check(self, ip_address, endpoint):
        """Stricter rate limiting for suspicious requests"""
        base_limits = self.endpoint_limits.get(endpoint, self.endpoint_limits['global'])
        strict_limits = {
            'requests': max(1, base_limits['requests'] // 2),
            'window': base_limits['window']
        }
        
        return self.rate_limit_check_with_limits(ip_address, endpoint, strict_limits)
    
    def is_suspicious_request(self, request):
        """Check if request is suspicious"""
        user_agent = request.headers.get('User-Agent', '').lower()
        
        # Check for headless browsers
        headless_indicators = [
            'headlesschrome', 'phantomjs', 'selenium', 'puppeteer'
        ]
        
        for indicator in headless_indicators:
            if indicator in user_agent:
                return True
        
        # Check for missing or suspicious headers
        if not user_agent:
            return True
        
        if 'accept' not in request.headers:
            return True
        
        # Check for known bad IPs
        if self.get_ip_reputation(request.remote_addr) > 30:
            return True
        
        return False
    
    def syn_flood_protection(self, ip_address):
        """Detect and mitigate SYN flood attacks"""
        syn_key = f"syn_flood:{ip_address}"
        
        if self.redis_client:
            try:
                syn_count = self.redis_client.incr(syn_key)
                
                if syn_count == 1:
                    self.redis_client.expire(syn_key, 1)  # 1 second window
                
                if syn_count > 100:  # More than 100 SYN requests per second
                    self.record_malicious_activity(ip_address, "SYN flood detected")
                    # Enable SYN cookies or other mitigation
                    return False
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed during SYN flood check")
                # Fall back to in-memory if Redis is unavailable
                return self.fallback_syn_flood_protection(ip_address)
        else:
            return self.fallback_syn_flood_protection(ip_address)
        
        return True
    
    def fallback_syn_flood_protection(self, ip_address):
        """Fallback SYN flood protection"""
        syn_key = f"syn_flood:{ip_address}"
        now = time.time()
        
        if syn_key in self.request_counts:
            count, timestamp = self.request_counts[syn_key]
            
            if now - timestamp < 1:  # 1 second window
                if count > 100:
                    self.record_malicious_activity(ip_address, "SYN flood detected")
                    return False
                
                self.request_counts[syn_key] = (count + 1, timestamp)
            else:
                self.request_counts[syn_key] = (1, now)
        else:
            self.request_counts[syn_key] = (1, now)
        
        return True
    
    def request_fingerprinting(self, request):
        """Create a fingerprint of the request for anomaly detection"""
        fingerprint_parts = [
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            request.remote_addr,
            request.path
        ]
        
        fingerprint = hashlib.md5('|'.join(fingerprint_parts).encode()).hexdigest()
        return fingerprint
    
    def detect_anomalous_traffic(self):
        """Detect traffic patterns indicative of DDoS"""
        fingerprint = self.request_fingerprinting(request)
        fingerprint_key = f"fingerprint:{fingerprint}"
        
        if self.redis_client:
            try:
                count = self.redis_client.incr(fingerprint_key)
                if count == 1:
                    self.redis_client.expire(fingerprint_key, 60)  # 1 minute window
                
                # If same request pattern occurs too frequently
                if count > 50:  # Adjust based on normal traffic patterns
                    return True
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed during fingerprint check")
                # Fall back to in-memory if Redis is unavailable
                return self.fallback_detect_anomalous_traffic(fingerprint)
        else:
            return self.fallback_detect_anomalous_traffic(fingerprint)
        
        return False
    
    def fallback_detect_anomalous_traffic(self, fingerprint):
        """Fallback anomalous traffic detection"""
        fingerprint_key = f"fingerprint:{fingerprint}"
        now = time.time()
        
        if fingerprint_key in self.request_counts:
            count, timestamp = self.request_counts[fingerprint_key]
            
            if now - timestamp < 60:  # 1 minute window
                if count > 50:
                    return True
                
                self.request_counts[fingerprint_key] = (count + 1, timestamp)
            else:
                self.request_counts[fingerprint_key] = (1, now)
        else:
            self.request_counts[fingerprint_key] = (1, now)
        
        return False
    
    def behavioral_check(self, request):
        """Analyze request behavior for bot detection"""
        # Use async check for better performance
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.async_behavioral_check(request))
        loop.close()
        return result
    
    async def async_behavioral_check(self, request):
        """Asynchronous behavioral check"""
        # Check IP reputation with external service if available
        if self.abuseipdb_key:
            is_malicious = await self.check_ip_reputation_async(request.remote_addr)
            if is_malicious:
                return False
        
        # Check for headless browsers
        user_agent = request.headers.get('User-Agent', '').lower()
        headless_indicators = ['headlesschrome', 'phantomjs', 'selenium', 'puppeteer']
        
        for indicator in headless_indicators:
            if indicator in user_agent:
                return False
        
        # Check for missing or suspicious headers
        if not user_agent or 'accept' not in request.headers:
            return False
        
        return True
    
    async def check_ip_reputation_async(self, ip_address):
        """Asynchronously check IP reputation with external services"""
        if not self.abuseipdb_key:
            return False
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}',
                                     headers={'Key': self.abuseipdb_key}) as response:
                    data = await response.json()
                    return data['data']['abuseConfidenceScore'] > 50
            except:
                return False
    
    def verify_challenge(self, challenge_id, answer):
        """Verify a JS challenge response"""
        if self.redis_client:
            try:
                expected = self.redis_client.get(f"challenge:{challenge_id}")
                if expected and int(expected) == int(answer):
                    self.redis_client.delete(f"challenge:{challenge_id}")
                    return True
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed during challenge verification")
                # Fall back to in-memory
                return self.fallback_verify_challenge(challenge_id, answer)
        
        # In-memory challenge verification
        return self.fallback_verify_challenge(challenge_id, answer)
    
    def fallback_verify_challenge(self, challenge_id, answer):
        """Fallback challenge verification"""
        if challenge_id in self.request_counts:
            expected, expiry = self.request_counts[challenge_id]
            if time.time() < expiry and int(expected) == int(answer):
                del self.request_counts[challenge_id]
                return True
        
        return False
    
    def should_require_captcha(self, ip_address):
        """Determine if CAPTCHA should be required"""
        # Require CAPTCHA after multiple violations
        reputation = self.get_ip_reputation(ip_address)
        return reputation > 30
    
    def captcha_response(self, ip_address):
        """Generate a CAPTCHA challenge response"""
        # In a real implementation, integrate with reCAPTCHA or hCaptcha
        # For now, we'll just redirect to a placeholder page
        return redirect(url_for('advanced_protection.captcha_verification', ip=ip_address))
    
    def is_api_request(self, request):
        """Check if request is an API request"""
        return request.path.startswith('/api/') or 'X-API-Key' in request.headers
    
    def validate_api_key(self, api_key):
        """Validate API key and check rate limits"""
        if not api_key:
            return False
        
        # Check if API key exists and is valid
        if api_key not in self.api_keys:
            return False
        
        # Check rate limits
        key_info = self.api_keys[api_key]
        limit = self.api_rate_limits.get(key_info.get('tier', 'default'), 1000)
        
        # Reset counter if hour has passed
        now = time.time()
        if now - key_info.get('last_reset', 0) > 3600:
            key_info['requests'] = 0
            key_info['last_reset'] = now
        
        if key_info['requests'] >= limit:
            return False
        
        key_info['requests'] += 1
        return True
    
    def ban_ip(self, ip_address, ban_time=300, reason="Violation"):
        """Ban an IP address for specified time"""
        ban_until = time.time() + ban_time
        
        if self.redis_client:
            try:
                self.redis_client.setex(f"ban:{ip_address}", ban_time, reason)
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory IP banning")
                self.banned_ips[ip_address] = (ban_until, reason)
        else:
            self.banned_ips[ip_address] = (ban_until, reason)
        
        logger.warning(f"IP {ip_address} banned until {datetime.fromtimestamp(ban_until)}. Reason: {reason}")
    
    def is_ip_banned(self, ip_address):
        """Check if IP is currently banned"""
        if self.redis_client:
            try:
                return bool(self.redis_client.exists(f"ban:{ip_address}"))
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory IP ban check")
                # Fall back to in-memory storage
                return self.fallback_is_ip_banned(ip_address)
        
        # In-memory IP ban check
        return self.fallback_is_ip_banned(ip_address)
    
    def fallback_is_ip_banned(self, ip_address):
        """Fallback IP ban check"""
        if ip_address in self.banned_ips:
            ban_until, reason = self.banned_ips[ip_address]
            if time.time() < ban_until:
                return True
            else:
                del self.banned_ips[ip_address]
        return False
    
    def unban_ip(self, ip_address):
        """Remove IP ban"""
        if self.redis_client:
            try:
                self.redis_client.delete(f"ban:{ip_address}")
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory IP unban")
                if ip_address in self.banned_ips:
                    del self.banned_ips[ip_address]
        else:
            if ip_address in self.banned_ips:
                del self.banned_ips[ip_address]
        
        logger.info(f"IP {ip_address} unbanned")
    
    def record_malicious_activity(self, ip_address, reason):
        """Record malicious activity and update IP reputation"""
        # Update reputation score
        current_score = self.get_ip_reputation(ip_address)
        new_score = current_score + 10  # Increase by 10 for each violation
        
        if self.redis_client:
            try:
                self.redis_client.setex(f"reputation:{ip_address}", 86400, new_score)  # 24 hours
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory reputation tracking")
                self.ip_reputation[ip_address] = (new_score, time.time() + 86400)
        else:
            self.ip_reputation[ip_address] = (new_score, time.time() + 86400)
        
        logger.warning(f"Malicious activity from {ip_address}: {reason}. Reputation: {new_score}")
    
    def get_ip_reputation(self, ip_address):
        """Get IP reputation score"""
        if self.redis_client:
            try:
                score = self.redis_client.get(f"reputation:{ip_address}")
                return int(score) if score else 0
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory reputation")
                # Fall back to in-memory storage
                return self.fallback_get_ip_reputation(ip_address)
        
        # In-memory reputation check
        return self.fallback_get_ip_reputation(ip_address)
    
    def fallback_get_ip_reputation(self, ip_address):
        """Fallback IP reputation check"""
        if ip_address in self.ip_reputation:
            score, expiry = self.ip_reputation[ip_address]
            if time.time() < expiry:
                return score
            else:
                del self.ip_reputation[ip_address]
        return 0
    
    def has_passed_challenge(self, ip_address):
        """Check if IP has recently passed a challenge"""
        if self.redis_client:
            try:
                return self.redis_client.exists(f"challenge_passed:{ip_address}")
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory challenge tracking")
                # Fall back to in-memory storage
                return self.fallback_has_passed_challenge(ip_address)
        
        # In-memory challenge check
        return self.fallback_has_passed_challenge(ip_address)
    
    def fallback_has_passed_challenge(self, ip_address):
        """Fallback challenge passed check"""
        key = f"challenge_passed:{ip_address}"
        if key in self.request_counts:
            passed, expiry = self.request_counts[key]
            if time.time() < expiry:
                return True
            else:
                del self.request_counts[key]
        return False
    
    def mark_challenge_passed(self, ip_address):
        """Mark that an IP has passed a challenge"""
        if self.redis_client:
            try:
                self.redis_client.setex(f"challenge_passed:{ip_address}", 3600, 1)  # 1 hour
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory challenge tracking")
                key = f"challenge_passed:{ip_address}"
                self.request_counts[key] = (True, time.time() + 3600)
        else:
            key = f"challenge_passed:{ip_address}"
            self.request_counts[key] = (True, time.time() + 3600)
    
    def js_challenge_response(self, ip_address):
        """Generate a JavaScript challenge response using a template"""
        # Generate a simple math challenge
        a = random.randint(1, 10)
        b = random.randint(1, 10)
        answer = a + b
        challenge_id = f"challenge_{int(time.time())}_{ip_address.replace('.', '_')}"
        
        # Store the expected answer
        if self.redis_client:
            try:
                self.redis_client.setex(f"challenge:{challenge_id}", 300, answer)
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, falling back to in-memory challenge storage")
                self.request_counts[challenge_id] = (answer, time.time() + 300)
        else:
            self.request_counts[challenge_id] = (answer, time.time() + 300)
        
        # Render the challenge template
        return render_template('advanced_protection/challenge.html', 
                             a=a, b=b, 
                             challenge_id=challenge_id,
                             next_url=request.url)
    
    def block_response(self, ip_address, reason):
        """Generate a block response using a template"""
        logger.warning(f"Blocking request from {ip_address}: {reason}")
        
        # Return a JSON response for API requests
        if self.is_api_request(request):
            return jsonify({
                'error': 'Access denied',
                'reason': reason,
                'ip': ip_address
            }), 429
        
        # Return HTML response for browser requests
        return render_template('advanced_protection/block.html', 
                             reason=reason, 
                             ip_address=ip_address), 429
    
    def get_stats(self):
        """Get protection statistics"""
        if self.redis_client:
            try:
                # This would need more complex implementation with Redis
                return {
                    'requests_blocked': 0,  # Would need to track this
                    'currently_banned': len(self.banned_ips),  # In-memory fallback
                    'total_tracked_ips': len(self.ip_reputation)  # In-memory fallback
                }
            except redis.exceptions.ConnectionError:
                logger.error("Redis connection failed, using in-memory stats")
                return {
                    'requests_blocked': sum(1 for ip, (_, reason) in self.banned_ips.items()),
                    'currently_banned': len(self.banned_ips),
                    'total_tracked_ips': len(self.ip_reputation)
                }
        else:
            return {
                'requests_blocked': sum(1 for ip, (_, reason) in self.banned_ips.items()),
                'currently_banned': len(self.banned_ips),
                'total_tracked_ips': len(self.ip_reputation)
            }
    
    def get_banned_ips(self):
        """Get all currently banned IPs with details"""
        banned_ips = {}
        
        if self.redis_client:
            try:
                # Get all banned IP keys from Redis
                banned_keys = self.redis_client.keys('ban:*')
                for key in banned_keys:
                    ip = key.decode().replace('ban:', '')
                    ttl = self.redis_client.ttl(key)
                    reason = self.redis_client.get(key).decode()
                    banned_ips[ip] = {
                        'banned_until': datetime.utcnow().timestamp() + ttl if ttl > 0 else 0,
                        'reason': reason
                    }
            except redis.exceptions.ConnectionError:
                logger.error("Error getting banned IPs from Redis, using in-memory data")
                # Fall back to in-memory storage
                for ip, (ban_until, reason) in self.banned_ips.items():
                    banned_ips[ip] = {
                        'banned_until': ban_until,
                        'reason': reason
                    }
            except Exception as e:
                logger.error(f"Error getting banned IPs from Redis: {e}")
        else:
            # Get from in-memory storage
            for ip, (ban_until, reason) in self.banned_ips.items():
                banned_ips[ip] = {
                    'banned_until': ban_until,
                    'reason': reason
                }
        
        # Format banned until timestamps
        for ip_info in banned_ips.values():
            if ip_info['banned_until']:
                ip_info['banned_until'] = datetime.fromtimestamp(ip_info['banned_until']).strftime('%Y-%m-%d %H:%M:%S')
        
        return banned_ips
    
    def get_system_load(self):
        """Get current system load"""
        try:
            # Get CPU load
            cpu_load = psutil.cpu_percent(interval=0.1) / 100
            
            # Get memory usage
            memory = psutil.virtual_memory()
            memory_load = memory.percent / 100
            
            # Return the higher of the two
            return max(cpu_load, memory_load)
        except:
            return 0  # Default to 0 if we can't get system load
    
    def prioritize_requests(self, request):
        """Assign priority to requests based on various factors"""
        # High priority: authenticated users, API requests with valid keys
        if current_user.is_authenticated:
            return 'high'
        
        if self.is_valid_api_request(request):
            return 'high'
        
        # Medium priority: known good IPs, important endpoints
        if self.is_known_good_ip(request.remote_addr):
            return 'medium'
        
        if request.path in ['/', '/login', '/health']:
            return 'medium'
        
        # Low priority: everything else
        return 'low'
    
    def is_valid_api_request(self, request):
        """Check if request has a valid API key"""
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        return api_key and api_key in self.api_keys
    
    def is_known_good_ip(self, ip_address):
        """Check if IP is in known good list"""
        # This would typically check against a whitelist
        return self.get_ip_reputation(ip_address) < 10  # Good reputation
    
    def should_shed_load(self):
        """Determine if load shedding should be activated"""
        system_load = self.get_system_load()
        request_rate = self.get_current_request_rate()
        
        if system_load > 0.9 or request_rate > self.config['MAX_REQUEST_RATE']:
            return True
        
        return False
    
    def get_current_request_rate(self):
        """Get current requests per second"""
        if self.redis_client:
            try:
                current_time = int(time.time())
                rps_key = f"rps:{current_time}"
                count = int(self.redis_client.get(rps_key) or 0)
                return count
            except:
                return 0
        else:
            # Fallback to in-memory tracking (less accurate)
            return 0
    
    def apply_load_shedding(self, request):
        """Apply load shedding based on request priority"""
        if not self.should_shed_load():
            return True  # Process request
        
        priority = self.prioritize_requests(request)
        
        # Shed load by rejecting low priority requests
        if priority == 'low' and random.random() < 0.7:  # Reject 70% of low priority
            return False
        
        if priority == 'medium' and random.random() < 0.3:  # Reject 30% of medium priority
            return False
        
        return True  # Process request
    
    def monitor_traffic_patterns(self):
        """Monitor traffic patterns for automatic adjustment"""
        current_time = time.time()
        window_size = 60  # 1 minute window
        
        # Track requests per second
        if self.redis_client:
            try:
                rps_key = f"rps:{int(current_time // window_size)}"
                self.redis_client.incr(rps_key)
                self.redis_client.expire(rps_key, window_size * 2)
                
                # Calculate current RPS
                current_window = int(current_time // window_size)
                previous_window = current_window - 1
                
                current_rps = int(self.redis_client.get(f"rps:{current_window}") or 0)
                previous_rps = int(self.redis_client.get(f"rps:{previous_window}") or 0)
                
                # Detect sudden traffic spikes
                if previous_rps > 0 and current_rps / previous_rps > 5:
                    self.trigger_ddos_mitigation()
                
                # Auto-adjust rate limits based on traffic
                self.auto_adjust_limits(current_rps)
            except:
                logger.error("Error monitoring traffic patterns")
    
    def trigger_ddos_mitigation(self):
        """Trigger DDoS mitigation measures"""
        logger.warning("DDoS mitigation triggered - traffic spike detected")
        
        # Switch to under_attack mode
        self.set_environment_mode('under_attack')
        
        # Increase logging
        logging.getLogger().setLevel(logging.WARNING)
        
        # Notify administrators (in a real implementation)
        # self.notify_administrators("DDoS mitigation triggered")
    
    def auto_adjust_limits(self, current_rps):
        """Automatically adjust rate limits based on current traffic"""
        base_limits = self.config['BASE_RATE_LIMITS'].copy()
        
        if current_rps > 1000:  # High traffic
            # Stricter limits during high traffic
            for endpoint in base_limits:
                base_limits[endpoint]['requests'] = max(1, base_limits[endpoint]['requests'] // 2)
        elif current_rps < 100:  # Low traffic
            # More lenient limits during low traffic
            for endpoint in base_limits:
                base_limits[endpoint]['requests'] = base_limits[endpoint]['requests'] * 2
        
        self.endpoint_limits = base_limits
    
    def integrate_with_cloudflare(self, ip_address):
        """Integrate with Cloudflare for additional DDoS protection"""
        if not self.cloudflare_api_key:
            return None  # Cloudflare not configured
        
        # Use Cloudflare's API to challenge suspicious requests
        if self.should_challenge_via_cloudflare(ip_address):
            # Redirect to Cloudflare challenge
            return redirect(self.generate_cloudflare_challenge_url(ip_address))
        
        return None
    
    def should_challenge_via_cloudflare(self, ip_address):
        """Determine if request should be challenged via Cloudflare"""
        reputation = self.get_ip_reputation(ip_address)
        request_rate = self.get_request_rate(ip_address)
        
        if reputation > 70 or request_rate > 100:  # Very suspicious
            return True
        
        return False
    
    def generate_cloudflare_challenge_url(self, ip_address):
        """Generate a Cloudflare challenge URL"""
        # This would use the Cloudflare API in a real implementation
        # For now, return a placeholder
        return f"https://challenge.cloudflare.com/?ip={ip_address}"
    
    def get_request_rate(self, ip_address):
        """Get request rate for a specific IP"""
        if self.redis_client:
            try:
                current_time = int(time.time())
                ip_rps_key = f"ip_rps:{ip_address}:{current_time}"
                count = int(self.redis_client.get(ip_rps_key) or 0)
                return count
            except:
                return 0
        else:
            return 0

# Create a global instance
advanced_protection = AdvancedProtection()

# Decorator for requiring protection on specific routes
def protect(route=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Let the protection middleware handle the request
            # This decorator is mainly for documentation and future enhancements
            return f(*args, **kwargs)
        return decorated_function
    return decorator
