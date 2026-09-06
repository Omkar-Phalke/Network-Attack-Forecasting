"""Stage 4: Cyber Kill Chain Attack State Estimator."""

from typing import Dict, Any, List, Optional
import pandas as pd
from src.config import KILL_CHAIN_STAGES
from src.utils.logger import get_logger

logger = get_logger("KillChainEstimator")

class KillChainEstimator:
    """Estimates the current operational stage of an adversary along the Cyber Kill Chain."""

    ATTACK_TO_STAGE = {
        "Benign": 0,
        "Reconnaissance": 1,
        "BruteForce": 2,
        "Infiltration": 3,
        "LateralMovement": 4,
        "Botnet_C2": 5,
        "DoS_DDoS": 6,
    }

    def __init__(self):
        # State tracking per source host: ip -> list of observed stages
        self.host_state_history = {}

    def estimate_stage(self, attack_class: str, flow_metadata: Optional[Dict[str, Any]] = None) -> int:
        """Determines the Kill Chain stage index [0..6] based on classification and context."""
        base_stage = self.ATTACK_TO_STAGE.get(attack_class, 0)
        if flow_metadata:
            # Contextual elevation: if an attacker already achieved Stage 2 and is now scanning internal subnets
            src = flow_metadata.get("Src IP")
            dst_port = flow_metadata.get("Dst Port", 0)
            cross_subnet = flow_metadata.get("cross_subnet_flag", 0)

            if src and src in self.host_state_history:
                max_past = max(self.host_state_history[src], default=0)
                if max_past >= 2 and cross_subnet and dst_port in [445, 3389, 22]:
                    return 4  # Elevate to Lateral Movement

        return base_stage

    def record_and_evaluate(self, src_ip: str, stage: int) -> Dict[str, Any]:
        """Records the latest state for a host and returns its cumulative progression."""
        if src_ip not in self.host_state_history:
            self.host_state_history[src_ip] = []
        self.host_state_history[src_ip].append(stage)

        max_stage = max(self.host_state_history[src_ip])
        stage_info = KILL_CHAIN_STAGES.get(max_stage, KILL_CHAIN_STAGES[0])

        return {
            "current_stage": stage,
            "max_observed_stage": max_stage,
            "stage_name": stage_info["name"],
            "severity": stage_info["severity"],
            "weight": stage_info["weight"],
            "history_depth": len(self.host_state_history[src_ip]),
        }
