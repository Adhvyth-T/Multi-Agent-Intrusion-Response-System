import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Config:
    # Database
    sqlite_path: str = "ir_system.db"
    
    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    
    # LLM APIs
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    openrouter_api_key: str = field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))
    openrouter_model: str = "arcee-ai/trinity-mini:free"
    
    # SMTP (using free services like Mailtrap, Mailhog, or Gmail)
    smtp_host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", "smtp.gmail.com"))
    smtp_port: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "587")))
    smtp_user: str = field(default_factory=lambda: os.getenv("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    alert_email: str = field(default_factory=lambda: os.getenv("ALERT_EMAIL", ""))
    
    # Trust Engine
    trust_level_1_max_actions: int = 50
    trust_level_2_max_actions: int = 150
    trust_level_3_max_actions: int = 500

config = Config()
