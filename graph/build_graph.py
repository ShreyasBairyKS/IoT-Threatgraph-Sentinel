import networkx as nx
import csv
import json
import argparse
from typing import List, Dict


_FEATURE_KEYS = [
    "flow_duration_mean",
    "packet_rate",
    "byte_volume",
    "port_entropy",
    "unique_dest_ips",
    "tcp_ratio",
    "udp_ratio",
    "iat_mean",
    "iat_std",
]


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _build_similarity_graph(rows: list[dict[str, str]]) -> nx.DiGraph:
    """
    Fallback graph build for feature-window datasets (no src/dst columns).

    Builds one node per device_id, computes mean feature vectors, then adds edges
    to top-K nearest peers by cosine similarity.
    """
    G = nx.DiGraph()
    by_device: dict[str, dict[str, object]] = {}

    for row in rows:
        device_id = (row.get("device_id") or "").strip()
        if not device_id:
            continue
        device_type = (row.get("device_type") or "unknown").strip() or "unknown"

        entry = by_device.setdefault(
            device_id,
            {
                "device_type": device_type,
                "sum": {k: 0.0 for k in _FEATURE_KEYS},
                "count": {k: 0 for k in _FEATURE_KEYS},
            },
        )
        entry["device_type"] = device_type

        sums = entry["sum"]
        counts = entry["count"]
        assert isinstance(sums, dict)
        assert isinstance(counts, dict)
        for key in _FEATURE_KEYS:
            fv = _to_float(row.get(key))
            if fv is None:
                continue
            sums[key] = float(sums.get(key, 0.0)) + fv
            counts[key] = int(counts.get(key, 0)) + 1

    vectors: dict[str, list[float]] = {}
    for device_id, data in by_device.items():
        sums = data["sum"]
        counts = data["count"]
        assert isinstance(sums, dict)
        assert isinstance(counts, dict)
        vec = []
        for key in _FEATURE_KEYS:
            cnt = int(counts.get(key, 0))
            total = float(sums.get(key, 0.0))
            vec.append((total / cnt) if cnt > 0 else 0.0)
        vectors[device_id] = vec
        G.add_node(device_id, device_type=str(data.get("device_type", "unknown")))

    ids = list(vectors.keys())
    if len(ids) < 2:
        return G

    # Feature-wise max for light normalization
    max_vals = [0.0] * len(_FEATURE_KEYS)
    for vec in vectors.values():
        for idx, value in enumerate(vec):
            if abs(value) > max_vals[idx]:
                max_vals[idx] = abs(value)
    max_vals = [m if m > 1e-9 else 1.0 for m in max_vals]

    norm: dict[str, list[float]] = {
        dev: [v / max_vals[i] for i, v in enumerate(vec)] for dev, vec in vectors.items()
    }

    def cosine(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b, strict=False))
        na = sum(x * x for x in a) ** 0.5
        nb = sum(y * y for y in b) ** 0.5
        if na <= 1e-12 or nb <= 1e-12:
            return 0.0
        return dot / (na * nb)

    k = min(3, len(ids) - 1)
    for src in ids:
        sims: list[tuple[str, float]] = []
        for dst in ids:
            if src == dst:
                continue
            score = cosine(norm[src], norm[dst])
            sims.append((dst, score))
        sims.sort(key=lambda x: x[1], reverse=True)
        for dst, score in sims[:k]:
            weight = max(1, int(round(score * 10)))
            G.add_edge(src, dst, weight=weight, similarity=round(score, 4))

    return G

def build_graph_from_flows(csv_path: str) -> nx.DiGraph:
    """
    Builds a directed graph from network flow data.
    Nodes are devices (or IPs).
    Edges represent communication between devices, weighted by frequency or volume.
    """
    G = nx.DiGraph()
    
    try:
        with open(csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

            if not rows:
                return G

            # Preferred path: explicit communication edges
            has_src_dst = any(
                ((row.get('src_ip') or '').strip() and (row.get('dst_ip') or '').strip())
                or ((row.get('source_device') or '').strip() and (row.get('target_device') or '').strip())
                for row in rows
            )

            if not has_src_dst:
                return _build_similarity_graph(rows)

            # Each row also carries its own device_id/device_type pair (used
            # elsewhere in the pipeline); tie that back to whichever edge
            # identifier corresponds to that device so nodes on the src/dst
            # path aren't left without a device_type (device-importance
            # weighting in graph/propagation.py depends on it).
            device_type_by_node: dict[str, str] = {}
            for row in rows:
                dev_type = (row.get('device_type') or '').strip()
                if not dev_type:
                    continue
                for key in ('device_id', 'src_ip', 'source_device'):
                    node_id = (row.get(key) or '').strip()
                    if node_id:
                        device_type_by_node.setdefault(node_id, dev_type)

            for row in rows:
                # The exact column names depend on the dataset (CIC-IoT-2023 / N-BaIoT)
                # Assuming generic names for now: 'src_ip', 'dst_ip'

                # In docs, device representations often use IDs like 'cam-001'.
                # We'll use source/dest as the node identifiers. Fall back to
                # the alternate column only when the preferred one is missing
                # OR blank (a present-but-empty 'src_ip'/'dst_ip' cell would
                # otherwise short-circuit `.get(key, default)` before ever
                # trying the fallback column).
                src = (row.get('src_ip') or row.get('source_device') or '').strip()
                dst = (row.get('dst_ip') or row.get('target_device') or '').strip()

                if not src or not dst:
                    continue

                if not G.has_node(src):
                    G.add_node(src, device_type=device_type_by_node.get(src, 'unknown'))
                if not G.has_node(dst):
                    G.add_node(dst, device_type=device_type_by_node.get(dst, 'unknown'))

                if G.has_edge(src, dst):
                    G[src][dst]['weight'] += 1
                else:
                    G.add_edge(src, dst, weight=1)
    except FileNotFoundError:
        print(f"Error: Dataset {csv_path} not found.")
        return G
        
    return G

def save_graph(G: nx.DiGraph, output_path: str):
    data = nx.node_link_data(G)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Graph saved to {output_path} with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")

def load_graph(input_path: str) -> nx.DiGraph:
    try:
        with open(input_path, 'r') as f:
            data = json.load(f)
        return nx.node_link_graph(data)
    except FileNotFoundError:
        print(f"Existing graph not found at {input_path}. Starting fresh.")
        return nx.DiGraph()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build network graph from flows.")
    parser.add_argument("--input", required=True, help="Path to input CSV flows")
    parser.add_argument("--output", default="artifacts/graph.json", help="Path to save graph JSON")
    
    args = parser.parse_args()
    
    # In a real streaming scenario, we might update an existing graph. 
    # For this script we build it from the CSV and save it.
    G = build_graph_from_flows(args.input)
    save_graph(G, args.output)
