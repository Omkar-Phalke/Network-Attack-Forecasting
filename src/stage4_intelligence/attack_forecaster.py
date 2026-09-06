"""Stage 4: Temporal Graph & Attack Forecasting Engine."""

from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from src.config import KILL_CHAIN_STAGES
from src.utils.logger import get_logger

logger = get_logger("AttackForecaster")

class AttackForecaster:
    """Predicts future cyber attack stages, time-to-impact (TTI), and projected target assets."""

    # Markov Transition Probability Matrix across Kill Chain Stages (0 to 6)
    DEFAULT_TRANSITION_MATRIX = np.array([
        # 0: Benign, 1: Recon, 2: Access, 3: Infil, 4: Lateral, 5: C2, 6: Exfil/DoS
        [0.92, 0.05, 0.02, 0.005, 0.003, 0.001, 0.001],  # From Benign
        [0.05, 0.20, 0.55, 0.12,  0.05,  0.02,  0.01],   # From Recon -> likely Initial Access
        [0.02, 0.05, 0.25, 0.45,  0.15,  0.05,  0.03],   # From Access -> likely Infiltration
        [0.01, 0.02, 0.05, 0.20,  0.50,  0.15,  0.07],   # From Infiltration -> likely Lateral Movement
        [0.01, 0.01, 0.02, 0.05,  0.25,  0.45,  0.21],   # From Lateral Movement -> likely C2 / Exfil
        [0.00, 0.00, 0.01, 0.02,  0.10,  0.25,  0.62],   # From C2 -> likely Exfil/DoS
        [0.05, 0.02, 0.01, 0.01,  0.05,  0.10,  0.76],   # From Exfil/DoS -> Impact sustained
    ])

    def __init__(self, transition_matrix: Optional[np.ndarray] = None):
        self.transition_matrix = transition_matrix if transition_matrix is not None else self.DEFAULT_TRANSITION_MATRIX

    def forecast_next_stage(self, current_stage: int, flow_rate: float = 1.0) -> Dict[str, Any]:
        """Forecasts next stage, transition probability, and estimated time-to-impact (minutes)."""
        current_stage = max(0, min(current_stage, 6))
        probs = self.transition_matrix[current_stage]

        # Candidates for future attack progression (exclude staying at Benign if current is attack)
        next_stage_probs = probs.copy()
        if current_stage > 0:
            # Look ahead to next escalation stages
            candidate_stages = np.arange(current_stage, 7)
            sub_probs = next_stage_probs[candidate_stages]
            if sub_probs.sum() > 0:
                sub_probs /= sub_probs.sum()
                predicted_stage = int(candidate_stages[np.argmax(sub_probs)])
                confidence = float(np.max(sub_probs))
            else:
                predicted_stage = min(current_stage + 1, 6)
                confidence = 0.50
        else:
            predicted_stage = int(np.argmax(next_stage_probs))
            confidence = float(next_stage_probs[predicted_stage])

        # Calculate Time-To-Impact (TTI) inversely proportional to flow velocity / burst rate
        base_lead_times = {
            0: 120.0, # Normal baseline
            1: 45.0,  # Recon: ~45 min before exploitation attempt
            2: 20.0,  # Brute force: ~20 min before breach
            3: 12.0,  # Infiltration: ~12 min before lateral movement
            4: 8.0,   # Lateral: ~8 min before reaching C2/core DB
            5: 4.0,   # C2: ~4 min before data exfiltration or DoS
            6: 0.0,   # Already impacting
        }
        lead_time = base_lead_times.get(current_stage, 30.0)
        # Adjust lead time by velocity: high connection rate speeds up attack execution
        velocity_factor = max(0.25, min(2.0, 1.0 / (np.log1p(flow_rate) + 0.1)))
        estimated_tti = round(lead_time * velocity_factor, 1)

        predicted_info = KILL_CHAIN_STAGES.get(predicted_stage, KILL_CHAIN_STAGES[0])

        return {
            "current_stage": current_stage,
            "predicted_next_stage": predicted_stage,
            "next_stage_name": predicted_info["name"],
            "next_stage_severity": predicted_info["severity"],
            "transition_probability": round(confidence, 3),
            "all_stage_probabilities": [round(float(p), 3) for p in probs],
            "estimated_time_to_impact_minutes": estimated_tti,
        }

    def forecast_trajectory(self, current_stage: int, steps: int = 3) -> List[Dict[str, Any]]:
        """Forecasts multi-step attack trajectory timeline."""
        trajectory = []
        curr = current_stage
        cumulative_time = 0.0

        for step in range(1, steps + 1):
            pred = self.forecast_next_stage(curr)
            curr = pred["predicted_next_stage"]
            cumulative_time += pred["estimated_time_to_impact_minutes"]
            trajectory.append({
                "step": step,
                "stage": curr,
                "stage_name": pred["next_stage_name"],
                "confidence": pred["transition_probability"],
                "projected_time_minutes": round(cumulative_time, 1),
            })
            if curr == 6:
                break

        return trajectory
