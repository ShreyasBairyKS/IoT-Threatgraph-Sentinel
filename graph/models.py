from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime

class FeatureWindow(BaseModel):
    window_start: datetime
    window_end: datetime
    device_id: str
    features: Dict[str, float]

class AnomalyScores(BaseModel):
    isolation_forest: float
    autoencoder: Optional[float] = None
    final_risk: float
    confidence: str

class AnomalyResult(BaseModel):
    timestamp: datetime
    device_id: str
    device_type: str
    scores: AnomalyScores
    reason_codes: List[str]
    explanations: List[str]

class NextTargetPrediction(BaseModel):
    device_id: str
    score: float
    why: str

class MitreTag(BaseModel):
    tactic: str
    technique: str

class GraphEnrichment(BaseModel):
    timestamp: datetime
    source_device: str
    propagation_risk: float
    neighbors: List[str]
    next_target_prediction: List[NextTargetPrediction]
    attack_paths: List[List[str]]
    mitre: MitreTag
