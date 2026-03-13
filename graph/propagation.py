import networkx as nx
import json
import argparse
from typing import Dict, List, Tuple
from datetime import datetime

from graph.models import AnomalyResult, GraphEnrichment, NextTargetPrediction, MitreTag

# MITRE ATT&CK Mapping
MITRE_MAPPING = {
    "outbound_volume_spike": MitreTag(tactic="Exfiltration", technique="T1048"),
    "dest_ip_diversity_jump": MitreTag(tactic="Lateral Movement", technique="T1021"),
    # Add more as needed based on P1's anomaly result payload reason codes.
}
DEFAULT_MITRE = MitreTag(tactic="Impact", technique="T1489") # Generic default

_DEVICE_IMPORTANCE: dict[str, float] = {
    "router": 1.0,
    "nvr": 0.95,
    "access_controller": 0.9,
    "camera": 0.75,
    "thermostat": 0.45,
    "sensor": 0.35,
    "smart_plug": 0.3,
}


def _importance_for_node(G: nx.DiGraph, node: str) -> float:
    device_type = str(G.nodes[node].get("device_type", "")).strip().lower() if G.has_node(node) else ""
    return _DEVICE_IMPORTANCE.get(device_type, 0.5)

def calculate_propagation_risk(G: nx.DiGraph, anomalous_node: str, base_risk: float) -> Tuple[float, List[NextTargetPrediction]]:
    """
    Calculates propagation risk and next likely targets.
    Uses personalized PageRank to find influential neighbors.
    """
    if not G.has_node(anomalous_node):
        return 0.0, []
        
    # Personalized PageRank starting mainly from the anomalous node
    personalization = {n: 0.0 for n in G.nodes()}
    personalization[anomalous_node] = 1.0
    
    try:
        pr = nx.pagerank(G, personalization=personalization, weight='weight')
    except Exception as e:
        print(f"PageRank error: {e}")
        pr = {n: 0.0 for n in G.nodes()}

    importance = _importance_for_node(G, anomalous_node)
    # Calculate propagation risk with importance weighting.
    propagation_risk = min(1.0, pr.get(anomalous_node, 0.0) * base_risk * (1.0 + importance))
    
    # Predict next targets based on outflowing edges and PageRank scores
    next_targets = []
    for neighbor in G.successors(anomalous_node):
        score = pr.get(neighbor, 0.0)
        why = "high flow volume" if G[anomalous_node][neighbor].get('weight', 0) > 5 else "frequent bidirectional flow"
        next_targets.append(NextTargetPrediction(device_id=neighbor, score=round(score, 3), why=why))
        
    next_targets.sort(key=lambda x: x.score, reverse=True)

    # Low-importance sources generally affect fewer next targets.
    max_targets = int(round(1 + importance * 3 + base_risk * 2))
    max_targets = max(1, min(6, max_targets))
    return round(propagation_risk, 3), next_targets[:max_targets]

def trace_attack_paths(G: nx.DiGraph, start_node: str, depth: int = 2) -> List[List[str]]:
    """
    Traces potential attack paths out of the anomalous node.
    """
    if not G.has_node(start_node):
        return []
        
    paths = []
    # Simple BFS to find paths up to `depth`
    def get_paths(current_node, current_path):
        if len(current_path) > depth:
            return
        paths.append(current_path)
        for neighbor in G.successors(current_node):
            if neighbor not in current_path: # Avoid loops
                get_paths(neighbor, current_path + [neighbor])
                
    get_paths(start_node, [start_node])
    
    # Filter out length-1 paths (just the root node)
    return [p for p in paths if len(p) > 1]
    
def map_mitre_tags(reason_codes: List[str]) -> MitreTag:
    for code in reason_codes:
        if code in MITRE_MAPPING:
            return MITRE_MAPPING[code]
    return DEFAULT_MITRE

def process_anomalies(graph_path: str, scores_path: str, output_path: str):
    try:
        with open(graph_path, 'r') as f:
            data = json.load(f)
            G = nx.node_link_graph(data)
    except Exception as e:
        print(f"Failed to load graph from {graph_path}: {e}")
        return

    try:
        with open(scores_path, 'r') as f:
            scores_data = json.load(f)
    except Exception as e:
        print(f"Failed to load scores from {scores_path}: {e}")
        return

    enrichments = []
    # If scores is a list of results
    if isinstance(scores_data, dict):
        if "items" in scores_data:
            scores_data = scores_data["items"]
        else:
            scores_data = [scores_data] # Force to list if single dict
            
    for raw_result in scores_data:
        try:
            result = AnomalyResult(**raw_result)
        except Exception as e:
            print(f"Invalid AnomalyResult payload: {e}")
            continue
            
        anomalous_device = result.device_id
        base_risk = result.scores.final_risk / 100.0 # Normalize to 0-1
        
        prop_risk, targets = calculate_propagation_risk(G, anomalous_device, base_risk)
        neighbors = list(G.successors(anomalous_device)) if G.has_node(anomalous_device) else []
        importance = _importance_for_node(G, anomalous_device)
        depth = 1 if importance < 0.4 else 2 if importance < 0.75 else 3
        attack_paths = trace_attack_paths(G, anomalous_device, depth=depth)
        mitre_tag = map_mitre_tags(result.reason_codes)
        
        enrichment = GraphEnrichment(
            timestamp=result.timestamp, # Pass timestamp from P1
            source_device=anomalous_device,
            propagation_risk=prop_risk,
            neighbors=neighbors,
            next_target_prediction=targets,
            attack_paths=attack_paths,
            mitre=mitre_tag
        )
        enrichments.append(enrichment.model_dump(mode='json'))

    # Save outputs
    with open(output_path, 'w') as f:
        json.dump(enrichments if len(enrichments) > 1 else enrichments[0], f, indent=2)
        
    print(f"Saved {len(enrichments)} enrichments to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate propagation risk and Graph Enrichment.")
    parser.add_argument("--graph", default="artifacts/graph.json", help="Path to graph JSON built by build_graph.py")
    parser.add_argument("--scores", required=True, help="Path to ML anomaly scores JSON")
    parser.add_argument("--output", default="artifacts/graph_enrichment.json", help="Path to output enrichment JSON")
    
    args = parser.parse_args()
    process_anomalies(args.graph, args.scores, args.output)
