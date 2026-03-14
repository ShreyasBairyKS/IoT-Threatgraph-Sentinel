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


DEFAULT_GRAPH_PATH = _env_str("IOT_GRAPH_PATH", "artifacts/graph.json")
DEFAULT_GRAPH_ENRICHMENT_PATH = _env_str("IOT_GRAPH_ENRICHMENT_PATH", "artifacts/graph_enrichment.json")

PAGERANK_EDGE_WEIGHT_KEY = _env_str("IOT_PAGERANK_WEIGHT_KEY", "weight")
PROPAGATION_RISK_MULTIPLIER = _env_float("IOT_PROPAGATION_RISK_MULTIPLIER", 1.5)
HIGH_FLOW_VOLUME_WEIGHT_THRESHOLD = _env_float("IOT_HIGH_FLOW_VOLUME_WEIGHT", 5.0)
NEXT_TARGET_TOP_K = _env_int("IOT_NEXT_TARGET_TOP_K", 5)
ATTACK_TRACE_DEPTH = _env_int("IOT_ATTACK_TRACE_DEPTH", 2)