import os
from dataclasses import dataclass, field


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
        """Reload configuration from environment variables."""
        self.LINEAR_API_KEY = os.getenv("LINEAR_API_KEY", "")
        self.LINEAR_TEAM_ID = os.getenv("LINEAR_TEAM_ID", "")
        self.LINEAR_PROJECT_ID = os.getenv("LINEAR_PROJECT_ID", "")
        self.LINEAR_DEFAULT_PRIORITY = int(os.getenv("LINEAR_DEFAULT_PRIORITY", "2"))
        self.SEMGREP_WEBHOOK_SECRET = os.getenv("SEMGREP_WEBHOOK_SECRET", "")
        self.PORT = int(os.getenv("PORT", "8080"))
        self.DEBUG = os.getenv("DEBUG", "false").lower() == "true"
        self.NGROK_AUTHTOKEN = os.getenv("NGROK_AUTHTOKEN", "")
        self.LOCAL_DEV = os.getenv("LOCAL_DEV", "false").lower() == "true"
        
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

