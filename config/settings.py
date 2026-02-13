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
    # Add these new fields to your existing Config dataclass:

    # Containment Agent
    DRY_RUN: bool = field(
        default_factory=lambda: os.getenv('IR_DRY_RUN', 'false').lower() == 'true'
    )
    
    ENABLE_SNAPSHOTS: bool = field(
        default_factory=lambda: os.getenv('IR_ENABLE_SNAPSHOTS', 'true').lower() == 'true'
    )
    
    ACTION_TIMEOUT: int = field(
        default_factory=lambda: int(os.getenv('IR_ACTION_TIMEOUT', '300'))
    )
    
    snapshot_storage_path: str = field(
        default_factory=lambda: os.getenv('IR_SNAPSHOT_PATH', '/tmp/ir-snapshots')
    )
    
    max_snapshot_size_bytes: int = field(
        default_factory=lambda: int(os.getenv('IR_MAX_SNAPSHOT_SIZE', str(50 * 1024 * 1024)))
    )
    
    collector_type: str = field(
        default_factory=lambda: os.getenv('IR_COLLECTOR', 'auto')
    )
    
    initial_trust_level: int = field(
        default_factory=lambda: int(os.getenv('IR_INITIAL_TRUST_LEVEL', '1'))
    )
config = Config()
