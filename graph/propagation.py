import networkx as nx
import json
import argparse
from typing import Dict, List, Tuple
from datetime import datetime

from graph.models import AnomalyResult, GraphEnrichment, NextTargetPrediction, MitreTag
from graph.settings import (
    ATTACK_TRACE_DEPTH,
    DEFAULT_GRAPH_ENRICHMENT_PATH,
    DEFAULT_GRAPH_PATH,
    HIGH_FLOW_VOLUME_WEIGHT_THRESHOLD,
    NEXT_TARGET_TOP_K,
    PAGERANK_EDGE_WEIGHT_KEY,
    PROPAGATION_RISK_MULTIPLIER,
)

# MITRE ATT&CK Mapping
MITRE_MAPPING = {
    "outbound_volume_spike": MitreTag(tactic="Exfiltration", technique="T1048"),
    "dest_ip_diversity_jump": MitreTag(tactic="Lateral Movement", technique="T1021"),
    # Add more as needed based on P1's anomaly result payload reason codes.
}
DEFAULT_MITRE = MitreTag(tactic="Impact", technique="T1489") # Generic default

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
        pr = nx.pagerank(G, personalization=personalization, weight=PAGERANK_EDGE_WEIGHT_KEY)
    except Exception as e:
        print(f"PageRank error: {e}")
        pr = {n: 0.0 for n in G.nodes()}

    # Calculate propagation risk: high if the node is highly central to the sub-graph
    propagation_risk = min(1.0, pr.get(anomalous_node, 0.0) * base_risk * PROPAGATION_RISK_MULTIPLIER)
    
    # Predict next targets based on outflowing edges and PageRank scores
    next_targets = []
    for neighbor in G.successors(anomalous_node):
        score = pr.get(neighbor, 0.0)
        why = (
            "high flow volume"
            if G[anomalous_node][neighbor].get('weight', 0) > HIGH_FLOW_VOLUME_WEIGHT_THRESHOLD
            else "frequent bidirectional flow"
        )
        next_targets.append(NextTargetPrediction(device_id=neighbor, score=round(score, 3), why=why))
        
    next_targets.sort(key=lambda x: x.score, reverse=True)
    return round(propagation_risk, 3), next_targets[:NEXT_TARGET_TOP_K]

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

def process_anomalies(graph_path: str, scores_path: str, output_path: str, api_url: str = None):
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
        attack_paths = trace_attack_paths(G, anomalous_device, depth=ATTACK_TRACE_DEPTH)
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

    # Real connection: push data to backend
    if api_url:
        import urllib.request
        for payload in enrichments:
            try:
                req = urllib.request.Request(
                    api_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req)
                print(f"Posted {payload.get('source_device')} graph enrichment to backend")
            except Exception as e:
                print(f"Warning: Failed to fallback/post graph enrichment: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate propagation risk and Graph Enrichment.")
    parser.add_argument("--graph", default=DEFAULT_GRAPH_PATH, help="Path to graph JSON built by build_graph.py")
    parser.add_argument("--scores", required=True, help="Path to ML anomaly scores JSON")
    parser.add_argument("--output", default=DEFAULT_GRAPH_ENRICHMENT_PATH, help="Path to output enrichment JSON")
    parser.add_argument("--api-url", default=None, help="Backend API URL to post results (e.g. http://localhost:8000/ingest/graph)")
    
    args = parser.parse_args()
    process_anomalies(args.graph, args.scores, args.output, args.api_url)
