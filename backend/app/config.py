import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings:
    APP_NAME = "DNS Tunneling Detection System"
    APP_VERSION = "1.0.0"
    DEBUG = os.getenv("DEBUG", "true").lower() == "true"
    
    DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/data/dns_tunneling.db")
    
    UPLOAD_DIR = BASE_DIR / "data" / "uploads"
    MAX_UPLOAD_SIZE = 100 * 1024 * 1024
    
    ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
    
    _cors_env = os.getenv("CORS_ORIGINS", "")
    CORS_ORIGINS = (
        [o.strip() for o in _cors_env.split(",") if o.strip()]
        if _cors_env
        else [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ]
    )
    
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

settings = Settings()

settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)