import os
import secrets
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelEdge"
    PROJECT_DESCRIPTION: str = "Secure Remote Workforce Monitoring Framework"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security & Tokens
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_hex(32))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Lockout & Rate limiting
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 30
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'sentineledge.db'}")
    
    # Paths
    STATIC_DIR: Path = BASE_DIR / "static"
    DATA_DIR: Path = BASE_DIR / "data"
    DOCS_DIR: Path = BASE_DIR / "docs"

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
