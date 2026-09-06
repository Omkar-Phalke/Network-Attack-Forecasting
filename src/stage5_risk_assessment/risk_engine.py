"""Stage 5: Dynamic Composite Cyber Risk Scoring Engine."""

from typing import Dict, Any, List, Optional
from src.config import RISK_LEVELS, KILL_CHAIN_STAGES, DEFAULT_CRITICALITY
from src.utils.logger import get_logger

logger = get_logger("RiskEngine")

class RiskScoringEngine:
    """Computes dynamic composite risk scores (0-100) combining threat, kill chain, asset criticality, and anomalies."""

    def __init__(
        self,
        weight_threat: float = 0.35,
        weight_stage: float = 0.30,
        weight_asset: float = 0.20,
        weight_anomaly: float = 0.15,
    ):
        self.w_threat = weight_threat
        self.w_stage = weight_stage
        self.w_asset = weight_asset
        self.w_anomaly = weight_anomaly

    def calculate_score(
        self,
        attack_prob: float,
        kill_chain_stage: int,
        asset_criticality: float = DEFAULT_CRITICALITY,
        anomaly_score: float = 0.0,
    ) -> Dict[str, Any]:
        """Calculates normalized composite risk score and assigns severity tier."""
        stage_info = KILL_CHAIN_STAGES.get(kill_chain_stage, KILL_CHAIN_STAGES[0])
        stage_weight = stage_info["weight"]

        raw_score = (
            (self.w_threat * attack_prob * 100.0)
            + (self.w_stage * stage_weight)
            + (self.w_asset * asset_criticality * 100.0)
            + (self.w_anomaly * anomaly_score * 100.0)
        )
        final_score = round(max(0.0, min(100.0, raw_score)), 1)

        # Categorize Severity Level
        severity = "Low"
        for level, threshold in RISK_LEVELS.items():
            if final_score >= threshold:
                severity = level
                break

        return {
            "risk_score": final_score,
            "risk_level": severity,
            "components": {
                "threat_contribution": round(self.w_threat * attack_prob * 100.0, 1),
                "kill_chain_contribution": round(self.w_stage * stage_weight, 1),
                "asset_contribution": round(self.w_asset * asset_criticality * 100.0, 1),
                "anomaly_contribution": round(self.w_anomaly * anomaly_score * 100.0, 1),
            },
            "stage_name": stage_info["name"],
        }
