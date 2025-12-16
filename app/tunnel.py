"""
Automatic ngrok tunnel management for local development.
"""
import os
import logging

logger = logging.getLogger(__name__)

# Global tunnel state
_tunnel = None
_public_url = None


def is_local_development() -> bool:
    """Check if we're running in local development mode."""
    # Check for explicit flag
    if os.getenv("LOCAL_DEV", "").lower() == "true":
        return True
    if os.getenv("AUTO_TUNNEL", "").lower() == "true":
        return True
    
    # Check if we're NOT in production indicators
    if os.getenv("RAILWAY_ENVIRONMENT"):
        return False
    if os.getenv("RENDER"):
        return False
    if os.getenv("FLY_APP_NAME"):
        return False
    if os.getenv("K_SERVICE"):  # Google Cloud Run
        return False
    if os.getenv("DYNO"):  # Heroku
        return False
    
    # Check if running on localhost/container without public URL
    # Default to checking LOCAL_DEV flag
    return os.getenv("LOCAL_DEV", "").lower() == "true"


def get_ngrok_auth_token() -> str:
    """Get ngrok auth token from environment or config."""
    return os.getenv("NGROK_AUTHTOKEN", "")


def start_tunnel(port: int = 8080) -> str:
    """Start ngrok tunnel and return public URL."""
    global _tunnel, _public_url
    
    if _public_url:
        return _public_url
    
    auth_token = get_ngrok_auth_token()
    if not auth_token:
        logger.warning(
            "NGROK_AUTHTOKEN not set. Get a free token at https://dashboard.ngrok.com/get-started/your-authtoken"
        )
        return None
    
    try:
        from pyngrok import ngrok, conf
        
        # Configure ngrok
        conf.get_default().auth_token = auth_token
        
        # Start tunnel
        _tunnel = ngrok.connect(port, bind_tls=True)
        _public_url = _tunnel.public_url
        
        logger.info(f"🚀 ngrok tunnel started: {_public_url}")
        logger.info(f"📋 Webhook URL for Semgrep: {_public_url}/webhook")
        
        return _public_url
        
    except Exception as e:
        logger.error(f"Failed to start ngrok tunnel: {e}")
        return None


def stop_tunnel():
    """Stop the ngrok tunnel."""
    global _tunnel, _public_url
    
    if _tunnel:
        try:
            from pyngrok import ngrok
            ngrok.disconnect(_tunnel.public_url)
            _tunnel = None
            _public_url = None
            logger.info("ngrok tunnel stopped")
        except Exception as e:
            logger.error(f"Error stopping tunnel: {e}")


def get_public_url() -> str:
    """Get the current public URL if tunnel is running."""
    return _public_url


def get_webhook_url(request_host: str = None) -> str:
    """
    Get the webhook URL to display to users.
    Returns ngrok URL if tunnel is running, otherwise constructs from request.
    """
    if _public_url:
        return f"{_public_url}/webhook"
    
    if request_host:
        # Determine protocol
        protocol = "https" if not request_host.startswith("localhost") else "http"
        return f"{protocol}://{request_host}/webhook"
    
    return "http://localhost:8080/webhook"

