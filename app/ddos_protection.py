import time
import redis
from collections import deque
from functools import wraps
from flask import request, jsonify, abort
from IPy import IP
import threading
import logging
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('DDoSProtection')

class DDoSProtection:
    def __init__(self, app=None, **kwargs):
        self.app = app
        self.redis_client = None
        self.use_redis = kwargs.get('use_redis', False)
        self.redis_url = kwargs.get('redis_url', 'redis://localhost:6379/0')
        self.requests_blocked = 0
        self.blocked_ips_log = {}
        
        # Configuration with default values
        self.config = {
            'REQUEST_LIMIT': kwargs.get('request_limit', 100),  # requests per window
            'WINDOW_SIZE': kwargs.get('window_size', 60),  # seconds
            'BAN_TIME': kwargs.get('ban_time', 300),  # seconds to ban an IP
            'AUTO_BAN': kwargs.get('auto_ban', True),  # automatically ban suspicious IPs
            'WHITELIST': kwargs.get('whitelist', []),  # list of whitelisted IPs/networks
            'BLACKLIST': kwargs.get('blacklist', []),  # list of blacklisted IPs/networks
            'TRUSTED_PROXIES': kwargs.get('trusted_proxies', []),  # list of trusted proxy IPs
            'ENABLE_LOGGING': kwargs.get('enable_logging', True),
            'MODE': kwargs.get('mode', 'monitor'),  # 'monitor', 'active', 'passive'
        }
        
        # In-memory storage if not using Redis
        self.request_logs = {}
        self.banned_ips = {}
        self.whitelist_ips = self._parse_ip_list(self.config['WHITELIST'])
        self.blacklist_ips = self._parse_ip_list(self.config['BLACKLIST'])
        self.trusted_proxies_ips = self._parse_ip_list(self.config['TRUSTED_PROXIES'])
        
        # Advanced detection patterns
        self.suspicious_patterns = [
            r"(\.\./)",  # Directory traversal
            r"(/\.env)",  # Environment file access
            r"(/wp-admin)",  # WordPress admin (common target)
            r"(/phpmyadmin)",  # phpMyAdmin access
            r"(/\.git)",  # Git directory access
            r"(union.*select)",  # SQL injection pattern
            r"(sleep\([\d]+\))",  # Time-based SQLi
        ]
        
        # Initialize Redis if enabled
        if self.use_redis:
            try:
                import redis
                self.redis_client = redis.from_url(self.redis_url)
                self.redis_client.ping()  # Test connection
                logger.info("Redis connected successfully")
            except Exception as e:
                logger.error(f"Redis connection failed: {e}")
                self.use_redis = False
        
        if app:
            self.init_app(app)
    
    def _parse_ip_list(self, ip_list):
        """Parse IP addresses and networks from a list"""
        parsed_ips = []
        for item in ip_list:
            try:
                # Check if it's a network range
                if '/' in item:
                    parsed_ips.append(IP(item))
                else:
                    parsed_ips.append(IP(item))
            except Exception as e:
                logger.warning(f"Invalid IP/network in list: {item} - {e}")
        return parsed_ips
    
    def _is_ip_in_list(self, ip, ip_list):
        """Check if an IP is in a list of IPs or networks"""
        try:
            ip_obj = IP(ip)
            for network in ip_list:
                if ip_obj in network:
                    return True
        except Exception as e:
            logger.warning(f"Error checking IP {ip}: {e}")
        return False
    
    def get_client_ip(self):
        """Get the real client IP address, considering proxies"""
        # Check trusted proxies first
        route = request.access_route
        if route and self.trusted_proxies_ips:
            for ip in reversed(route):
                if not self._is_ip_in_list(ip, self.trusted_proxies_ips):
                    return ip
        # Fallback to standard method
        return request.remote_addr
    
    def init_app(self, app):
        """Initialize the Flask application with DDoS protection"""
        self.app = app
        
        # Add before request handler
        @app.before_request
        def check_ddos_protection():
            # Skip if protection is in monitor mode
            if self.config['MODE'] == 'monitor':
                return
            
            client_ip = self.get_client_ip()
            
            # Check if IP is whitelisted
            if self._is_ip_in_list(client_ip, self.whitelist_ips):
                return
            
            # Check if IP is blacklisted
            if self._is_ip_in_list(client_ip, self.blacklist_ips):
                if self.config['ENABLE_LOGGING']:
                    logger.warning(f"Blacklisted IP attempted access: {client_ip}")
                abort(403)
            
            # Check if IP is temporarily banned
            if self.is_banned(client_ip):
                if self.config['ENABLE_LOGGING']:
                    logger.warning(f"Banned IP attempted access: {client_ip}")
                abort(429)
            
            # Check request rate
            if self.is_rate_limited(client_ip):
                if self.config['AUTO_BAN']:
                    self.ban_ip(client_ip, self.config['BAN_TIME'])
                if self.config['ENABLE_LOGGING']:
                    logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                abort(429)
            
            # Check for suspicious patterns in request
            if self.has_suspicious_patterns(request):
                if self.config['AUTO_BAN']:
                    self.ban_ip(client_ip, self.config['BAN_TIME'] * 2)  # Longer ban
                if self.config['ENABLE_LOGGING']:
                    logger.warning(f"Suspicious request pattern from IP: {client_ip}")
                abort(403)
    
    def is_rate_limited(self, ip):
        """Check if an IP has exceeded the rate limit"""
        current_time = time.time()
        window_size = self.config['WINDOW_SIZE']
        request_limit = self.config['REQUEST_LIMIT']
        
        if self.use_redis and self.redis_client:
            # Use Redis for rate limiting
            key = f"ddos:{ip}"
            try:
                # Get current count
                count = self.redis_client.get(key)
                if count is None:
                    count = 0
                    self.redis_client.setex(key, window_size, 1)
                else:
                    count = int(count)
                    if count >= request_limit:
                        return True
                    self.redis_client.incr(key)
                
                return False
            except Exception as e:
                logger.error(f"Redis error: {e}")
                # Fallback to in-memory storage
                self.use_redis = False
        
        # In-memory rate limiting
        if ip not in self.request_logs:
            self.request_logs[ip] = deque(maxlen=request_limit * 2)
        
        # Remove timestamps outside the current window
        while (self.request_logs[ip] and 
               current_time - self.request_logs[ip][0] > window_size):
            self.request_logs[ip].popleft()
        
        # Check if limit exceeded
        if len(self.request_logs[ip]) >= request_limit:
            return True
        
        # Log the request
        self.request_logs[ip].append(current_time)
        return False
    
    def has_suspicious_patterns(self, request):
        """Check if the request has suspicious patterns"""
        path = request.path.lower()
        user_agent = request.headers.get('User-Agent', '').lower()
        
        # Check path for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern in path:
                return True
        
        # Check for suspicious user agents
        suspicious_agents = [
            'sqlmap', 'nikto', 'metasploit', 'nessus', 
            'acunetix', 'dirbuster', 'wpscan', 'nmap'
        ]
        
        for agent in suspicious_agents:
            if agent in user_agent:
                return True
        
        return False
    
    def ban_ip(self, ip, ban_time=None):
        """Ban an IP address for a specified time"""
        if ban_time is None:
            ban_time = self.config['BAN_TIME']
        
        ban_until = time.time() + ban_time
        
        if self.use_redis and self.redis_client:
            try:
                self.redis_client.setex(f"ban:{ip}", ban_time, 1)
            except Exception as e:
                logger.error(f"Redis ban error: {e}")
                self.use_redis = False
        
        # In-memory ban
        self.banned_ips[ip] = ban_until
        
        if self.config['ENABLE_LOGGING']:
            logger.warning(f"IP banned: {ip} until {datetime.fromtimestamp(ban_until)}")
    
    def is_banned(self, ip):
        """Check if an IP is currently banned"""
        if self.use_redis and self.redis_client:
            try:
                return self.redis_client.exists(f"ban:{ip}")
            except Exception as e:
                logger.error(f"Redis ban check error: {e}")
                self.use_redis = False
        
        # Check in-memory bans
        if ip in self.banned_ips:
            if time.time() > self.banned_ips[ip]:
                # Ban expired, remove it
                del self.banned_ips[ip]
                return False
            return True
        return False
    
    def unban_ip(self, ip):
        """Remove ban from an IP address"""
        if self.use_redis and self.redis_client:
            try:
                self.redis_client.delete(f"ban:{ip}")
            except Exception as e:
                logger.error(f"Redis unban error: {e}")
        
        if ip in self.banned_ips:
            del self.banned_ips[ip]
        
        if self.config['ENABLE_LOGGING']:
            logger.info(f"IP unbanned: {ip}")
    
    def get_stats(self, ip=None):
        """Get statistics for an IP or all IPs"""
        if ip:
            if self.use_redis and self.redis_client:
                try:
                    count = self.redis_client.get(f"ddos:{ip}")
                    banned = self.redis_client.exists(f"ban:{ip}")
                    return {
                            'ip': ip,
                            'request_count': int(count) if count else 0,
                            'banned': bool(banned)
                            }
                except Exception as e:
                    logger.error(f"Redis stats error: {e}")
                # In-memory stats
                request_count = len(self.request_logs.get(ip, []))
                banned = ip in self.banned_ips and time.time() < self.banned_ips[ip]
                return {
                            'ip': ip,
                            'request_count': request_count,
                            'banned': banned
                            }
        else:
                    # Return overall stats with the fields your template expects
                    currently_banned = len([ip for ip in self.banned_ips if time.time() < self.banned_ips[ip]])

                    # For Redis, we need to count banned IPs differently
                    if self.use_redis and self.redis_client:
                        try:
                            banned_keys = self.redis_client.keys('ban:*')
                            currently_banned = len(banned_keys)
                        except Exception as e:
                            logger.error(f"Error counting banned IPs from Redis: {e}")
                            return {
                                    'total_tracked_ips': len(self.request_logs),
                                    'currently_banned': currently_banned,
                                    'ips_banned': currently_banned,  # Add this for template compatibility
                                    'ips_tracked': len(self.request_logs),  # Add this for template compatibility
                                    'requests_blocked': 'N/A',  # You'll need to implement request blocking tracking
                                    'mode': self.config['MODE'],
                                    'using_redis': self.use_redis
                                    }
    
    def middleware(self, f):
        """Decorator for applying DDoS protection to specific routes"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip if protection is in monitor mode
            if self.config['MODE'] == 'monitor':
                return f(*args, **kwargs)
            
            client_ip = self.get_client_ip()
            
            # Check if IP is whitelisted
            if self._is_ip_in_list(client_ip, self.whitelist_ips):
                return f(*args, **kwargs)
            
            # Check if IP is blacklisted
            if self._is_ip_in_list(client_ip, self.blacklist_ips):
                if self.config['ENABLE_LOGGING']:
                    logger.warning(f"Blacklisted IP attempted access: {client_ip}")
                abort(403)
            
            # Check if IP is temporarily banned
            if self.is_banned(client_ip):
                if self.config['ENABLE_LOGGING']:
                    logger.warning(f"Banned IP attempted access: {client_ip}")
                abort(429)
            
            # Check request rate
            if self.is_rate_limited(client_ip):
                if self.config['AUTO_BAN']:
                    self.ban_ip(client_ip, self.config['BAN_TIME'])
                if self.config['ENABLE_LOGGING']:
                    logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                abort(429)
            
            # Check for suspicious patterns in request
            if self.has_suspicious_patterns(request):
                if self.config['AUTO_BAN']:
                    self.ban_ip(client_ip, self.config['BAN_TIME'] * 2)
                if self.config['ENABLE_LOGGING']:
                    logger.warning(f"Suspicious request pattern from IP: {client_ip}")
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function

# Create a global instance
ddos_protection = DDoSProtection()
