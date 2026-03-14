"""
config.py - Application configuration via environment variables.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    APP_NAME: str = "IoT ThreatGraph Sentinel - API Server"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # WebSocket broadcaster interval (seconds) in mock mode
    WS_MOCK_INTERVAL_SECONDS: float = 3.0

    # Real-time synthetic stream interval (seconds)
    REALTIME_STREAM_INTERVAL_SECONDS: float = 5.0

    # Enable continuous real-time feeder for local development/demo
    REALTIME_STREAM_ENABLED: bool = True

    # Polling fallback interval for clients that cannot use WebSocket
    POLL_FALLBACK_INTERVAL_SECONDS: int = 3

    # PDF generation timeout (seconds)
    PDF_GENERATION_TIMEOUT: int = 5

    # In-memory store limit for recent alerts
    MAX_ALERT_STORE: int = 500

    # Risk thresholds mapping to severity levels
    ALERT_RISK_THRESHOLD: float = 60.0
    SEVERITY_CRITICAL_THRESHOLD: float = 85.0
    SEVERITY_HIGH_THRESHOLD: float = 70.0
    SEVERITY_MEDIUM_THRESHOLD: float = 50.0

    # Confidence thresholds
    CONFIDENCE_HIGH_THRESHOLD: float = 80.0
    CONFIDENCE_MEDIUM_THRESHOLD: float = 50.0


settings = Settings()
