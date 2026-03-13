"""Compatibility re-exports for graph package models.

Canonical inter-service contracts live in ``backend.contracts``.
This module exists only to preserve older imports in graph tests/scripts.
"""

from backend.contracts import (
    AnomalyResult,
    AnomalyScores,
    FeatureWindow,
    GraphEnrichment,
    MITRETag,
    NextTargetPrediction,
)

# Backward-compatible alias used by older graph-side imports.
MitreTag = MITRETag
