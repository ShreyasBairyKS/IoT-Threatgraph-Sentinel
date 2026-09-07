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

    # Synthetic stream interval (seconds) for continuous backend feed generation.
    SYNTHETIC_STREAM_INTERVAL_SECONDS: float = 10.0

    # Enable synthetic stream in runtime (auto-disabled during pytest by app lifespan).
    SYNTHETIC_STREAM_ENABLED: bool = True

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

    # Risk threshold above which an AnomalyResult becomes an AlertEvent.
    # Calibrated at 65.0 on the synthetic test set (F1=0.857 @ threshold=65).
    # Override via env var: ALERT_RISK_THRESHOLD=70
    ALERT_RISK_THRESHOLD: float = 65.0

    # Single switch for a real deployment: set DEMO_MODE=false to disable all
    # synthetic/demo data generation regardless of the individual stream
    # flags below, instead of having to know to flip each one separately.
    DEMO_MODE: bool = True

    # Shared-secret API key required on POST /ingest/* when set. Left empty
    # by default so local development and the existing test suite keep
    # working unauthenticated; set INGEST_API_KEY to lock ingestion down for
    # a real deployment (send it back as the X-API-Key header).
    INGEST_API_KEY: str = ""

    # In-memory per-client rate limit on POST /ingest/* (protects the one
    # unauthenticated-by-default trust boundary from abuse/flooding).
    INGEST_RATE_LIMIT_MAX_REQUESTS: int = 100
    INGEST_RATE_LIMIT_WINDOW_SECONDS: float = 10.0


settings = Settings()
