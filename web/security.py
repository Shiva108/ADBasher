"""
Security utilities for input sanitization and rate limiting
"""

import html
import re
from functools import wraps
from flask import request, jsonify
from datetime import datetime, timedelta
from collections import defaultdict
import threading

# Simple in-memory rate limiter
class RateLimiter:
    """Simple rate limiter for API endpoints"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, key, max_requests=10, window_seconds=60):
        """Check if request is allowed under rate limit"""
        now = datetime.now()
        window_start = now - timedelta(seconds=window_seconds)
        
        with self.lock:
            # Clean old requests
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if req_time > window_start
            ]
            
            # Check limit
            if len(self.requests[key]) >= max_requests:
                return False
            
            # Add current request
            self.requests[key].append(now)
            return True

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(max_requests=10, window_seconds=60):
    """Decorator for rate limiting API endpoints"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Use IP address as key
            client_ip = request.remote_addr
            
            if not rate_limiter.is_allowed(client_ip, max_requests, window_seconds):
                return jsonify({
                    'error': 'Rate limit exceeded. Please try again later.'
                }), 429
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

def sanitize_html(text):
    """Escape HTML to prevent XSS"""
    if not isinstance(text, str):
        return text
    return html.escape(text)

def sanitize_campaign_data(data):
    """Sanitize all string fields in campaign data"""
    if isinstance(data, dict):
        return {
            key: sanitize_campaign_data(value)
            for key, value in data.items()
        }
    elif isinstance(data, list):
        return [sanitize_campaign_data(item) for item in data]
    elif isinstance(data, str) and key != 'password':  # Don't sanitize passwords
        return sanitize_html(data)
    else:
        return data

def validate_content_type(required='application/json'):
    """Decorator to validate Content-Type header"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'PATCH']:
                content_type = request.headers.get('Content-Type', '')
                if required not in content_type:
                    return jsonify({
                        'error': f'Invalid Content-Type. Expected {required}'
                    }), 415
            return f(*args, **kwargs)
        return wrapper
    return decorator
