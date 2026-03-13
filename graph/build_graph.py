import networkx as nx
import csv
import json
import argparse
from typing import List, Dict

def build_graph_from_flows(csv_path: str) -> nx.DiGraph:
    """
    Builds a directed graph from network flow data.
    Nodes are devices (or IPs).
    Edges represent communication between devices, weighted by frequency or volume.

    Supports both the synthetic IoT dataset columns (src_device / dst_device)
    and raw IP-based columns (src_ip / dst_ip / source_device / target_device).
    """
    G = nx.DiGraph()
    
    try:
        with open(csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Prefer logical device IDs; fall back to IP addresses
                src = (
                    row.get('src_device')
                    or row.get('source_device')
                    or row.get('src_ip')
                    or 'unknown_src'
                )
                dst = (
                    row.get('dst_device')
                    or row.get('target_device')
                    or row.get('dst_ip')
                    or 'unknown_dst'
                )
                
                if src == 'unknown_src' or dst == 'unknown_dst':
                    continue
                
                if not G.has_node(src):
                    G.add_node(src)
                if not G.has_node(dst):
                    G.add_node(dst)
                    
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
