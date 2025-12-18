import os
from dataclasses import dataclass, field
from pathlib import Path


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
    
    # Ngrok Configuration
    NGROK_AUTHTOKEN: str = ""
    LOCAL_DEV: bool = False
    
    # Severity to Priority Mapping (Semgrep severity -> Linear priority 1-4)
    SEVERITY_PRIORITY_MAP: dict = field(default_factory=dict)
    
    def __post_init__(self):
        self.reload()
    
    def reload(self):
        """Reload configuration from .env file and environment variables."""
        # First load from .env file (takes precedence for saved config)
        env_file = _load_env_file()
        
        # Then check environment variables, with .env file taking precedence
        self.LINEAR_API_KEY = env_file.get("LINEAR_API_KEY") or os.getenv("LINEAR_API_KEY", "")
        self.LINEAR_TEAM_ID = env_file.get("LINEAR_TEAM_ID") or os.getenv("LINEAR_TEAM_ID", "")
        self.LINEAR_PROJECT_ID = env_file.get("LINEAR_PROJECT_ID") or os.getenv("LINEAR_PROJECT_ID", "")
        self.LINEAR_DEFAULT_PRIORITY = int(env_file.get("LINEAR_DEFAULT_PRIORITY") or os.getenv("LINEAR_DEFAULT_PRIORITY", "2"))
        self.SEMGREP_WEBHOOK_SECRET = env_file.get("SEMGREP_WEBHOOK_SECRET") or os.getenv("SEMGREP_WEBHOOK_SECRET", "")
        self.PORT = int(env_file.get("PORT") or os.getenv("PORT", "8080"))
        self.DEBUG = (env_file.get("DEBUG") or os.getenv("DEBUG", "false")).lower() == "true"
        self.NGROK_AUTHTOKEN = env_file.get("NGROK_AUTHTOKEN") or os.getenv("NGROK_AUTHTOKEN", "")
        self.LOCAL_DEV = (env_file.get("LOCAL_DEV") or os.getenv("LOCAL_DEV", "false")).lower() == "true"
        
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


# Singleton config instance
config = Config()

