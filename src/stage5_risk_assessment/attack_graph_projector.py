"""Stage 5: Future Attack Graph (Predicted) Projector."""

from typing import Dict, Any, List, Set
import networkx as nx
from src.config import CRITICAL_ASSETS, DEFAULT_CRITICALITY
from src.utils.logger import get_logger

logger = get_logger("AttackGraphProjector")

class AttackGraphProjector:
    """Projects future attack propagation paths and vulnerable network assets."""

    def __init__(self, topology_graph: nx.DiGraph):
        self.topology_graph = topology_graph

    def project_future_attack_graph(
        self,
        compromised_ips: List[str],
        forecasted_stage: int,
        steps: int = 2
    ) -> Dict[str, Any]:
        """Generates future predicted attack graph showing anticipated attacker pivot hops."""
        predicted_nodes = []
        predicted_edges = []
        visited_nodes: Set[str] = set(compromised_ips)

        # Baseline compromised nodes
        for ip in compromised_ips:
            meta = CRITICAL_ASSETS.get(ip, {})
            predicted_nodes.append({
                "id": ip,
                "label": f"{ip}\n(Compromised / Attacker)",
                "color": {"background": "#ef4444", "border": "#ffffff"},
                "shape": "diamond",
                "size": 28,
                "status": "Compromised",
            })

        # Calculate propagation candidates based on asset criticality and kill-chain stage
        for comp_ip in compromised_ips:
            # Candidate targets from critical assets inventory
            for target_ip, target_meta in CRITICAL_ASSETS.items():
                if target_ip in visited_nodes:
                    continue

                crit = target_meta.get("criticality", DEFAULT_CRITICALITY)
                role = target_meta.get("role", "Host")

                # Higher likelihood if moving to auth or database in later stages
                if forecasted_stage in [3, 4] and role in ["Identity/Auth", "Database", "Web DMZ"]:
                    prob = round(0.65 + 0.30 * crit, 2)
                elif forecasted_stage >= 5:
                    prob = round(0.80 + 0.15 * crit, 2)
                else:
                    prob = round(0.40 + 0.30 * crit, 2)

                predicted_nodes.append({
                    "id": target_ip,
                    "label": f"{target_ip}\n({role})\n[Targeted]",
                    "color": {"background": "#f97316" if prob >= 0.75 else "#eab308", "border": "#ffffff"},
                    "shape": "dot",
                    "size": 22 + int(crit * 16),
                    "status": "Predicted Target",
                    "compromise_probability": prob,
                })
                visited_nodes.add(target_ip)

                # Add projected directed edge
                predicted_edges.append({
                    "from": comp_ip,
                    "to": target_ip,
                    "label": f"Projected Pivot ({int(prob * 100)}%)",
                    "color": {"color": "#ef4444"},
                    "dashes": True,
                    "arrows": "to",
                    "width": 3,
                })

        return {
            "forecasted_kill_chain_stage": forecasted_stage,
            "projected_nodes": predicted_nodes,
            "projected_edges": predicted_edges,
            "high_risk_target_count": len([n for n in predicted_nodes if n.get("status") == "Predicted Target"]),
        }
