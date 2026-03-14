from __future__ import annotations

import os


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    return raw if raw else default


def _env_int_tuple(name: str, default: tuple[int, ...]) -> tuple[int, ...]:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        values = tuple(int(part.strip()) for part in raw.split(",") if part.strip())
    except ValueError:
        return default
    return values if values else default


DEFAULT_MODEL_DIR = _env_str("IOT_MODEL_DIR", "artifacts/models")

TRAIN_IF_N_ESTIMATORS = _env_int("IOT_IF_N_ESTIMATORS", 200)
TRAIN_IF_CONTAMINATION = _env_float("IOT_IF_CONTAMINATION", 0.05)
TRAIN_RF_N_ESTIMATORS = _env_int("IOT_RF_N_ESTIMATORS", 200)
TRAIN_AE_HIDDEN_SIZES = _env_int_tuple("IOT_AE_HIDDEN_SIZES", (16, 8, 16))
TRAIN_AE_MAX_ITER = _env_int("IOT_AE_MAX_ITER", 500)

CONFIDENCE_HIGH_THRESHOLD = _env_float("IOT_CONF_HIGH", 80.0)
CONFIDENCE_MEDIUM_THRESHOLD = _env_float("IOT_CONF_MEDIUM", 50.0)

REASON_MIN_RISK = _env_float("IOT_REASON_MIN_RISK", 70.0)
REASON_MIN_EXPLANATIONS_HIGH_RISK = _env_int("IOT_REASON_MIN_EXPLANATIONS_HIGH", 2)
RULE_BYTE_VOLUME_THRESHOLD = _env_float("IOT_REASON_BYTE_VOLUME", 50_000.0)
RULE_DEST_IP_THRESHOLD = _env_float("IOT_REASON_DEST_IPS", 5.0)
RULE_PORT_ENTROPY_THRESHOLD = _env_float("IOT_REASON_PORT_ENTROPY", 2.0)
RULE_PACKET_RATE_THRESHOLD = _env_float("IOT_REASON_PACKET_RATE", 40.0)
RULE_UDP_RATIO_THRESHOLD = _env_float("IOT_REASON_UDP_RATIO", 0.5)

HEURISTIC_BYTE_LOG_WEIGHT = _env_float("IOT_HEURISTIC_BYTE_LOG_WEIGHT", 8.0)
HEURISTIC_PACKET_RATE_WEIGHT = _env_float("IOT_HEURISTIC_PACKET_RATE_WEIGHT", 0.6)
HEURISTIC_UNIQUE_DEST_WEIGHT = _env_float("IOT_HEURISTIC_UNIQUE_DEST_WEIGHT", 3.5)
HEURISTIC_PORT_ENTROPY_WEIGHT = _env_float("IOT_HEURISTIC_PORT_ENTROPY_WEIGHT", 10.0)