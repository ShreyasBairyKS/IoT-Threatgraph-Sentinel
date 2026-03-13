import pytest
import networkx as nx
from datetime import datetime
from graph.models import GraphEnrichment, MitreTag, NextTargetPrediction, AnomalyResult, AnomalyScores
from graph.propagation import calculate_propagation_risk, trace_attack_paths, map_mitre_tags

@pytest.fixture
def sample_graph():
    G = nx.DiGraph()
    G.add_edge("cam-001", "router-02", weight=10)
    G.add_edge("router-02", "nvr-01", weight=5)
    G.add_edge("router-02", "sensor-07", weight=2)
    G.add_edge("cam-001", "sensor-07", weight=1)
    return G

def test_calculate_propagation_risk(sample_graph):
    # Base risk is normalized 0-1
    risk, targets = calculate_propagation_risk(sample_graph, "cam-001", 0.73)
    
    # We expect some calculated risk based on PageRank
    assert isinstance(risk, float)
    assert 0.0 <= risk <= 1.0
    
    # "cam-001" points to router-02 and sensor-07. 
    # router-02 should be the highest weighted next target
    assert len(targets) > 0
    assert targets[0].device_id == "router-02"
    assert targets[0].score > 0
    
def test_trace_attack_paths(sample_graph):
    paths = trace_attack_paths(sample_graph, "cam-001", depth=3)
    
    assert len(paths) > 0
    # Expected paths should include cam-001 -> router-02 -> nvr-01
    found = False
    for path in paths:
        if path == ["cam-001", "router-02", "nvr-01"]:
            found = True
            break
            
    assert found

def test_map_mitre_tags():
    # Test valid mapping
    tag = map_mitre_tags(["dest_ip_diversity_jump", "other_reason"])
    assert tag.tactic == "Lateral Movement"
    assert tag.technique == "T1021"
    
    # Test default
    tag = map_mitre_tags(["unknown_reason"])
    assert tag.tactic == "Impact"
    assert tag.technique == "T1489"
