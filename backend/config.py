"""
config.py - Application configuration via environment variables.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    APP_NAME: str = "IoT ThreatGraph Sentinel - API Server"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # Enable mock/demo fallbacks only when explicitly requested.
    ENABLE_MOCK_DATA: bool = False

    # WebSocket broadcaster interval (seconds) in mock mode
    WS_MOCK_INTERVAL_SECONDS: float = 3.0

    # Polling fallback interval for clients that cannot use WebSocket
    POLL_FALLBACK_INTERVAL_SECONDS: int = 3

    # PDF generation timeout (seconds)
    PDF_GENERATION_TIMEOUT: int = 5

    # In-memory store limit for recent alerts
    MAX_ALERT_STORE: int = 500

    # Risk threshold above which an AnomalyResult becomes an AlertEvent.
    # Calibrated at 65.0 on the synthetic test set (F1=0.857 @ threshold=65).
    # Override via env var: ALERT_RISK_THRESHOLD=70
    ALERT_RISK_THRESHOLD: float = 65.0


settings = Settings()
