import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _load_env_file():
    """Load environment variables from .env file."""
    env_vars = {}
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars


@dataclass
class Config:
    """Application configuration loaded from environment variables."""
    
    # Linear API Configuration
    LINEAR_API_KEY: str = ""
    LINEAR_TEAM_ID: str = ""
    LINEAR_PROJECT_ID: str = ""
    LINEAR_DEFAULT_PRIORITY: int = 2
    
    # Semgrep Webhook Configuration
    SEMGREP_WEBHOOK_SECRET: str = ""
    
    # Application Configuration
    PORT: int = 8080
    DEBUG: bool = False
    
    # Production Mode - enforces security best practices
    PRODUCTION: bool = False
    
    # Dashboard Authentication (required in production)
    DASHBOARD_API_KEY: str = ""
    DASHBOARD_USERNAME: str = ""
    DASHBOARD_PASSWORD: str = ""
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # "json" or "text"
    LOG_FILE: str = ""  # Path to log file (empty = stdout only)
    
    # Activity Log Persistence
    ACTIVITY_LOG_FILE: str = ""  # Path to persist activity log
    ACTIVITY_LOG_MAX_SIZE_MB: int = 10
    
    # Ngrok Configuration (local dev only)
    NGROK_AUTHTOKEN: str = ""
    LOCAL_DEV: bool = False
    
    # Linear API Configuration
    LINEAR_API_TIMEOUT: int = 30
    LINEAR_API_RETRIES: int = 3
    LINEAR_API_RETRY_DELAY: float = 1.0
    
    # Webhook Configuration
    WEBHOOK_MAX_PAYLOAD_SIZE_KB: int = 1024  # 1MB max
    
    # Severity to Priority Mapping (Semgrep severity -> Linear priority 1-4)
    SEVERITY_PRIORITY_MAP: dict = field(default_factory=dict)
    
    def __post_init__(self):
        self.reload()
    
    def reload(self):
        """Reload configuration from .env file and environment variables."""
        # First load from .env file (takes precedence for saved config)
        env_file = _load_env_file()
        
        def get_config(key: str, default: str = "") -> str:
            return env_file.get(key) or os.getenv(key, default)
        
        def get_bool(key: str, default: bool = False) -> bool:
            return get_config(key, str(default)).lower() in ("true", "1", "yes")
        
        def get_int(key: str, default: int) -> int:
            try:
                return int(get_config(key, str(default)))
            except ValueError:
                return default
        
        def get_float(key: str, default: float) -> float:
            try:
                return float(get_config(key, str(default)))
            except ValueError:
                return default
        
        # Core Configuration
        self.LINEAR_API_KEY = get_config("LINEAR_API_KEY")
        self.LINEAR_TEAM_ID = get_config("LINEAR_TEAM_ID")
        self.LINEAR_PROJECT_ID = get_config("LINEAR_PROJECT_ID")
        self.LINEAR_DEFAULT_PRIORITY = get_int("LINEAR_DEFAULT_PRIORITY", 2)
        self.SEMGREP_WEBHOOK_SECRET = get_config("SEMGREP_WEBHOOK_SECRET")
        self.PORT = get_int("PORT", 8080)
        self.DEBUG = get_bool("DEBUG", False)
        
        # Production Mode
        self.PRODUCTION = get_bool("PRODUCTION", False)
        
        # Dashboard Authentication
        self.DASHBOARD_API_KEY = get_config("DASHBOARD_API_KEY")
        self.DASHBOARD_USERNAME = get_config("DASHBOARD_USERNAME")
        self.DASHBOARD_PASSWORD = get_config("DASHBOARD_PASSWORD")
        
        # Rate Limiting
        self.RATE_LIMIT_PER_MINUTE = get_int("RATE_LIMIT_PER_MINUTE", 60)
        self.RATE_LIMIT_BURST = get_int("RATE_LIMIT_BURST", 10)
        
        # Logging
        self.LOG_LEVEL = get_config("LOG_LEVEL", "INFO").upper()
        self.LOG_FORMAT = get_config("LOG_FORMAT", "json" if self.PRODUCTION else "text")
        self.LOG_FILE = get_config("LOG_FILE")
        
        # Activity Log
        self.ACTIVITY_LOG_FILE = get_config("ACTIVITY_LOG_FILE")
        self.ACTIVITY_LOG_MAX_SIZE_MB = get_int("ACTIVITY_LOG_MAX_SIZE_MB", 10)
        
        # Local Dev / ngrok
        self.NGROK_AUTHTOKEN = get_config("NGROK_AUTHTOKEN")
        self.LOCAL_DEV = get_bool("LOCAL_DEV", False)
        
        # Linear API
        self.LINEAR_API_TIMEOUT = get_int("LINEAR_API_TIMEOUT", 30)
        self.LINEAR_API_RETRIES = get_int("LINEAR_API_RETRIES", 3)
        self.LINEAR_API_RETRY_DELAY = get_float("LINEAR_API_RETRY_DELAY", 1.0)
        
        # Webhook
        self.WEBHOOK_MAX_PAYLOAD_SIZE_KB = get_int("WEBHOOK_MAX_PAYLOAD_SIZE_KB", 1024)
        
        self.SEVERITY_PRIORITY_MAP = {
            "critical": 1,  # Urgent
            "high": 1,      # Urgent
            "medium": 2,    # High
            "low": 3,       # Medium
            "info": 4,      # Low
        }
    
    def validate(self) -> list:
        """Validate required configuration."""
        errors = []
        if not self.LINEAR_API_KEY:
            errors.append("LINEAR_API_KEY is required")
        if not self.LINEAR_TEAM_ID:
            errors.append("LINEAR_TEAM_ID is required")
        return errors
    
    def validate_production(self) -> list:
        """Validate configuration for production deployment."""
        errors = self.validate()
        
        if self.PRODUCTION:
            # In production, webhook secret should be set for security
            if not self.SEMGREP_WEBHOOK_SECRET:
                errors.append("SEMGREP_WEBHOOK_SECRET is required in production mode")
            
            # Dashboard should be protected
            if not self.DASHBOARD_API_KEY and not (self.DASHBOARD_USERNAME and self.DASHBOARD_PASSWORD):
                errors.append("Dashboard authentication required in production (set DASHBOARD_API_KEY or DASHBOARD_USERNAME/DASHBOARD_PASSWORD)")
            
            # Local dev should be disabled
            if self.LOCAL_DEV:
                errors.append("LOCAL_DEV should be false in production")
            
            # Debug should be disabled
            if self.DEBUG:
                errors.append("DEBUG should be false in production")
        
        return errors
    
    def is_dashboard_auth_enabled(self) -> bool:
        """Check if dashboard authentication is configured."""
        return bool(self.DASHBOARD_API_KEY or (self.DASHBOARD_USERNAME and self.DASHBOARD_PASSWORD))
    
    def generate_api_key(self) -> str:
        """Generate a secure API key."""
        return f"slw_{secrets.token_urlsafe(32)}"


# Singleton config instance
config = Config()
