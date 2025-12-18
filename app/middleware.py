"""
Production middleware for authentication, rate limiting, and request validation.
"""
import time
import base64
import logging
from functools import wraps
from collections import defaultdict
from threading import Lock
from flask import request, jsonify, g

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple in-memory rate limiter using token bucket algorithm."""
    
    def __init__(self, rate_per_minute: int = 60, burst: int = 10):
        self.rate = rate_per_minute / 60.0  # tokens per second
        self.burst = burst
        self.tokens = defaultdict(lambda: burst)
        self.last_update = defaultdict(time.time)
        self._lock = Lock()
    
    def is_allowed(self, key: str) -> tuple[bool, dict]:
        """
        Check if request is allowed.
        Returns (allowed, headers) where headers include rate limit info.
        """
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update[key]
            self.last_update[key] = now
            
            # Add tokens based on elapsed time
            self.tokens[key] = min(
                self.burst,
                self.tokens[key] + elapsed * self.rate
            )
            
            headers = {
                "X-RateLimit-Limit": str(int(self.rate * 60)),
                "X-RateLimit-Remaining": str(int(self.tokens[key])),
                "X-RateLimit-Reset": str(int(now + (self.burst - self.tokens[key]) / self.rate))
            }
            
            if self.tokens[key] >= 1:
                self.tokens[key] -= 1
                return True, headers
            
            return False, headers


# Global rate limiter instance
_rate_limiter = None


def init_rate_limiter(rate_per_minute: int = 60, burst: int = 10):
    """Initialize the global rate limiter."""
    global _rate_limiter
    _rate_limiter = RateLimiter(rate_per_minute, burst)


def rate_limit(f):
    """Decorator to apply rate limiting to a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if _rate_limiter is None:
            return f(*args, **kwargs)
        
        # Use IP address as rate limit key
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if client_ip and "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
        
        allowed, headers = _rate_limiter.is_allowed(client_ip)
        
        # Always add rate limit headers to response
        response = None
        if not allowed:
            response = jsonify({"error": "Rate limit exceeded"}), 429
        else:
            response = f(*args, **kwargs)
        
        # Handle tuple responses (response, status_code)
        if isinstance(response, tuple):
            resp, code = response
            if hasattr(resp, "headers"):
                for key, value in headers.items():
                    resp.headers[key] = value
            return resp, code
        
        # Handle direct response objects
        if hasattr(response, "headers"):
            for key, value in headers.items():
                response.headers[key] = value
        
        return response
    
    return decorated_function


def require_auth(config):
    """
    Decorator factory to require authentication for a route.
    Supports API key (header) or Basic Auth.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip auth if not configured
            if not config.is_dashboard_auth_enabled():
                return f(*args, **kwargs)
            
            # Check API key in header
            api_key = request.headers.get("X-API-Key")
            if api_key and config.DASHBOARD_API_KEY:
                if api_key == config.DASHBOARD_API_KEY:
                    g.auth_method = "api_key"
                    return f(*args, **kwargs)
            
            # Check Basic Auth
            auth = request.authorization
            if auth and config.DASHBOARD_USERNAME and config.DASHBOARD_PASSWORD:
                if auth.username == config.DASHBOARD_USERNAME and auth.password == config.DASHBOARD_PASSWORD:
                    g.auth_method = "basic"
                    return f(*args, **kwargs)
            
            # Check API key in query param (for browser access)
            api_key_param = request.args.get("api_key")
            if api_key_param and config.DASHBOARD_API_KEY:
                if api_key_param == config.DASHBOARD_API_KEY:
                    g.auth_method = "api_key_param"
                    return f(*args, **kwargs)
            
            # Return 401 with WWW-Authenticate header for browser auth prompt
            response = jsonify({"error": "Authentication required"})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = 'Basic realm="Semgrep-Linear Dashboard"'
            return response
        
        return decorated_function
    return decorator


def validate_webhook_payload(max_size_kb: int = 1024):
    """
    Decorator to validate webhook payload size.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            content_length = request.content_length
            
            if content_length and content_length > max_size_kb * 1024:
                logger.warning(f"Webhook payload too large: {content_length} bytes")
                return jsonify({"error": "Payload too large"}), 413
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def log_request():
    """Decorator to log request details."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            
            # Execute the route
            response = f(*args, **kwargs)
            
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Get response code
            status_code = response[1] if isinstance(response, tuple) else (
                response.status_code if hasattr(response, "status_code") else 200
            )
            
            # Log the request
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            logger.info(
                f"{request.method} {request.path} - {status_code} - {duration_ms:.1f}ms - {client_ip}"
            )
            
            return response
        
        return decorated_function
    return decorator

