"""Stage 6: What-If Counterfactual Simulator (Future Risk Change)."""

from typing import Dict, Any, List, Optional
from src.config import RISK_LEVELS, KILL_CHAIN_STAGES
from src.utils.logger import get_logger

logger = get_logger("WhatIfSimulator")

class WhatIfSimulator:
    """Simulates counterfactual security interventions and projects future risk reduction."""

    @staticmethod
    def simulate_intervention(
        pre_risk_score: float,
        pre_kill_chain_stage: int,
        block_source_ip: bool = False,
        rate_limit_ports: Optional[List[int]] = None,
        quarantine_host: bool = False,
        restrict_cross_subnet: bool = False,
    ) -> Dict[str, Any]:
        """Calculates counterfactual post-intervention risk and delta."""
        reduction = 0.0
        applied_controls = []

        if block_source_ip:
            reduction += 55.0
            applied_controls.append("Perimeter firewall dropped all traffic from attacking IP")

        if quarantine_host:
            reduction += 45.0
            applied_controls.append("Compromised host isolated onto quarantine VLAN")

        if rate_limit_ports and len(rate_limit_ports) > 0:
            reduction += 25.0
            applied_controls.append(f"Rate-limiting engaged on ports: {rate_limit_ports}")

        if restrict_cross_subnet:
            reduction += 20.0
            applied_controls.append("Zero-Trust cross-subnet ACL enforcement applied")

        # Post-intervention risk score
        post_risk_score = round(max(5.0, pre_risk_score - reduction), 1)
        delta_risk = round(post_risk_score - pre_risk_score, 1)

        # Projected new kill chain stage after containment
        if block_source_ip or quarantine_host:
            projected_stage = 0  # Contained / neutralized
        elif rate_limit_ports:
            projected_stage = max(0, pre_kill_chain_stage - 1)
        else:
            projected_stage = pre_kill_chain_stage

        # Post severity
        post_severity = "Low"
        for level, threshold in RISK_LEVELS.items():
            if post_risk_score >= threshold:
                post_severity = level
                break

        return {
            "baseline_risk_score": pre_risk_score,
            "simulated_risk_score": post_risk_score,
            "delta_risk": delta_risk,
            "risk_reduction_percentage": round((abs(delta_risk) / max(1.0, pre_risk_score)) * 100.0, 1),
            "simulated_risk_level": post_severity,
            "projected_kill_chain_stage": projected_stage,
            "projected_stage_name": KILL_CHAIN_STAGES.get(projected_stage, {})["name"],
            "containment_status": "CONTAINED" if post_risk_score < 35.0 else "PARTIALLY_MITIGATED",
            "applied_interventions": applied_controls,
        }
