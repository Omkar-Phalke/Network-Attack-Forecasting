"""Stage 3: Dynamic Host Communication Graph Builder G(V, E)."""

from typing import Dict, Any, List, Tuple
import networkx as nx
import pandas as pd
from src.config import CRITICAL_ASSETS, DEFAULT_CRITICALITY
from src.utils.logger import get_logger

logger = get_logger("GraphBuilder")

class HostGraphBuilder:
    """Builds and analyzes dynamic host interaction graphs G = (V, E)."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_from_dataframe(self, df: pd.DataFrame) -> nx.DiGraph:
        """Constructs a directed graph from network flows."""
        self.graph = nx.DiGraph()

        # Iterate over flows to populate nodes and aggregated edges
        for _, row in df.iterrows():
            src = str(row.get("Src IP", "0.0.0.0"))
            dst = str(row.get("Dst IP", "0.0.0.0"))
            bytes_sent = float(row.get("TotLen Fwd Pkts", 0.0) or 0.0)
            packets = int(row.get("Tot Fwd Pkts", 1.0) or 1.0)
            port = int(row.get("Dst Port", 0) or 0)
            label = str(row.get("Label", "Benign"))

            # Add source node
            if src not in self.graph:
                src_meta = CRITICAL_ASSETS.get(src, {})
                self.graph.add_node(
                    src,
                    label=src,
                    name=src_meta.get("name", f"Host {src}"),
                    role=src_meta.get("role", "Host"),
                    criticality=src_meta.get("criticality", DEFAULT_CRITICALITY),
                    threat_level="Normal",
                )

            # Add destination node
            if dst not in self.graph:
                dst_meta = CRITICAL_ASSETS.get(dst, {})
                self.graph.add_node(
                    dst,
                    label=dst,
                    name=dst_meta.get("name", f"Host {dst}"),
                    role=dst_meta.get("role", "Host"),
                    criticality=dst_meta.get("criticality", DEFAULT_CRITICALITY),
                    threat_level="Normal",
                )

            # Add or update edge
            if self.graph.has_edge(src, dst):
                edge_data = self.graph[src][dst]
                edge_data["weight"] += bytes_sent
                edge_data["packet_count"] += packets
                edge_data["ports"].add(port)
                if label != "Benign":
                    edge_data["is_malicious"] = True
            else:
                self.graph.add_edge(
                    src,
                    dst,
                    weight=bytes_sent,
                    packet_count=packets,
                    ports={port},
                    is_malicious=(label != "Benign"),
                )

        return self.graph

    def compute_graph_metrics(self, df: pd.DataFrame) -> pd.DataFrame:
        """Computes node centralities and maps them back into flow DataFrame features."""
        df = df.copy()
        if len(self.graph.nodes) == 0:
            self.build_from_dataframe(df)

        try:
            in_degree_cent = nx.in_degree_centrality(self.graph)
            out_degree_cent = nx.out_degree_centrality(self.graph)
            pagerank_cent = nx.pagerank(self.graph, max_iter=200)
        except Exception:
            in_degree_cent = {n: 0.0 for n in self.graph.nodes}
            out_degree_cent = {n: 0.0 for n in self.graph.nodes}
            pagerank_cent = {n: 0.0 for n in self.graph.nodes}

        df["host_in_degree_centrality"] = df["Dst IP"].astype(str).map(in_degree_cent).fillna(0.0)
        df["host_out_degree_centrality"] = df["Src IP"].astype(str).map(out_degree_cent).fillna(0.0)
        df["host_pagerank"] = df["Dst IP"].astype(str).map(pagerank_cent).fillna(0.0)

        return df

    def to_visualization_json(self) -> Dict[str, Any]:
        """Converts graph to Vis.js-compatible node and edge dictionaries."""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            role = data.get("role", "Host")
            criticality = data.get("criticality", DEFAULT_CRITICALITY)
            threat = data.get("threat_level", "Normal")

            # Determine node color based on threat status
            color = "#10b981"  # green (normal)
            if threat == "Critical":
                color = "#ef4444"  # red
            elif threat == "High":
                color = "#f97316"  # orange
            elif threat == "Medium":
                color = "#eab308"  # yellow

            nodes.append({
                "id": node_id,
                "label": f"{node_id}\n({role})",
                "title": f"{data.get('name')}<br>Role: {role}<br>Criticality: {criticality}<br>Status: {threat}",
                "color": {"background": color, "border": "#ffffff"},
                "shape": "dot" if role == "Workstation" else "diamond",
                "size": 20 + int(criticality * 20),
            })

        edges = []
        for src, dst, data in self.graph.edges(data=True):
            is_mal = data.get("is_malicious", False)
            edges.append({
                "from": src,
                "to": dst,
                "label": f"{int(data.get('packet_count', 0))} pkts",
                "color": {"color": "#ef4444" if is_mal else "#64748b"},
                "arrows": "to",
                "dashes": is_mal,
                "width": max(1, min(6, int(data.get("weight", 0) / 10000) + 1)),
            })

        return {"nodes": nodes, "edges": edges}
