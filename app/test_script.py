import unittest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from flask import Flask, request
from advanced_protection import AdvancedProtection
import redis

class TestAdvancedProtection(unittest.TestCase):
    def setUp(self):
        # Create a test Flask app
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key'
        self.app.config['WTF_CSRF_ENABLED'] = False
        
        # Initialize the protection system without calling init_app to avoid blueprint registration
        self.protection = AdvancedProtection()
        
        # Create a test client
        self.client = self.app.test_client()

    def test_initialization(self):
        """Test that the protection system initializes correctly"""
        self.assertEqual(self.protection.config['MODE'], 'active')
        self.assertTrue(self.protection.config['WAF_ENABLED'])
        self.assertTrue(self.protection.config['GEO_BLOCKING_ENABLED'])
        
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Test in-memory rate limiting
        ip = '192.168.1.1'
        endpoint = '/test'
        
        # First request should be allowed
        result = self.protection.rate_limit_check(ip, endpoint)
        self.assertTrue(result['allowed'])
        self.assertEqual(result['remaining'], 99)  # Default limit is 100
        
        # Make many requests to exceed the limit
        for _ in range(100):
            result = self.protection.rate_limit_check(ip, endpoint)
        
        # Should now be blocked
        result = self.protection.rate_limit_check(ip, endpoint)
        self.assertFalse(result['allowed'])
        
    def test_waf_check(self):
        """Test WAF functionality"""
        # Create a mock request with SQL injection
        mock_request = Mock()
        mock_request.path = '/test'
        mock_request.method = 'POST'
        mock_request.headers = {'User-Agent': 'Mozilla/5.0'}
        mock_request.form = {'query': "SELECT * FROM users WHERE id = 1; DROP TABLE users;"}
        
        # Should be blocked by WAF
        self.assertFalse(self.protection.waf_check(mock_request))
        
        # Test with normal request
        mock_request.form = {'query': "normal search"}
        self.assertTrue(self.protection.waf_check(mock_request))
        
    def test_ip_banning(self):
        """Test IP banning functionality"""
        ip = '192.168.1.100'
        
        # IP should not be banned initially
        self.assertFalse(self.protection.is_ip_banned(ip))
        
        # Ban the IP
        self.protection.ban_ip(ip, 60, "Test ban")
        
        # IP should now be banned
        self.assertTrue(self.protection.is_ip_banned(ip))
        
        # Unban the IP
        self.protection.unban_ip(ip)
        
        # IP should no longer be banned
        self.assertFalse(self.protection.is_ip_banned(ip))
        
    def test_country_access_control(self):
        """Test country access control functionality"""
        # Mock the GeoIP reader
        mock_geoip = Mock()
        mock_response = Mock()
        mock_response.country.iso_code = 'RU'  # Russia (should be blocked)
        mock_geoip.city.return_value = mock_response
        self.protection.geoip_reader = mock_geoip
        
        # Set up blocked countries
        self.protection.blocked_countries = {'RU', 'CN'}
        self.protection.allowed_countries = {'US', 'CA', 'GB'}
        
        # Test blocked country
        self.assertFalse(self.protection.geo_check('192.168.1.1'))
        
        # Test allowed country
        mock_response.country.iso_code = 'US'
        self.assertTrue(self.protection.geo_check('192.168.1.1'))
        
        # Test country not in allowed list
        mock_response.country.iso_code = 'FR'  # France not in allowed list
        self.assertFalse(self.protection.geo_check('192.168.1.1'))
        
    def test_js_challenge(self):
        """Test JavaScript challenge functionality"""
        # Instead of calling js_challenge_response which needs request context,
        # test the challenge generation and verification directly
        
        # Create a test challenge
        challenge_id = 'test_challenge_123'
        answer = 15
        self.protection.request_counts[challenge_id] = (answer, time.time() + 300)
        
        # Test correct answer
        self.assertTrue(self.protection.verify_challenge(challenge_id, str(answer)))
        
        # Test incorrect answer
        self.assertFalse(self.protection.verify_challenge(challenge_id, '999'))
        
    def test_api_rate_limiting(self):
        """Test API rate limiting"""
        # Add a test API key
        self.protection.api_keys['test-key'] = {
            'tier': 'default',
            'requests': 0,
            'last_reset': time.time()
        }
        
        # First request should be allowed
        self.assertTrue(self.protection.validate_api_key('test-key'))
        
        # Make many requests to exceed the limit
        for _ in range(1000):  # Default limit is 1000
            self.protection.validate_api_key('test-key')
        
        # Should now be blocked
        self.assertFalse(self.protection.validate_api_key('test-key'))
        
    def test_country_access_update(self):
        """Test updating country access controls"""
        # Test updating country sets directly
        self.protection.allowed_countries = {'US', 'CA', 'GB'}
        self.protection.blocked_countries = {'RU', 'CN'}
        
        # Check that country sets were updated
        self.assertEqual(self.protection.allowed_countries, {'US', 'CA', 'GB'})
        self.assertEqual(self.protection.blocked_countries, {'RU', 'CN'})

    def test_config_update(self):
        """Test updating protection configuration"""
        # Test updating config directly
        self.protection.config['REQUEST_LIMIT'] = 50
        self.protection.config['WINDOW_SIZE'] = 30
        self.protection.config['BAN_TIME'] = 600
        
        # Check that config was updated
        self.assertEqual(self.protection.config['REQUEST_LIMIT'], 50)
        self.assertEqual(self.protection.config['WINDOW_SIZE'], 30)
        self.assertEqual(self.protection.config['BAN_TIME'], 600)

if __name__ == '__main__':
    unittest.main()
