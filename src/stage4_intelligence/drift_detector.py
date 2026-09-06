"""Stage 4: Continuous Learning & Statistical Drift Detection."""

from typing import Dict, Any, List
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp
from src.utils.logger import get_logger

logger = get_logger("DriftDetector")

class DriftDetector:
    """Monitors incoming network flow distribution for feature and concept drift."""

    def __init__(self, baseline_df: pd.DataFrame, monitored_features: List[str]):
        self.monitored_features = [f for f in monitored_features if f in baseline_df.columns]
        self.baseline_stats = {}

        # Store baseline quantiles for each feature
        for feat in self.monitored_features:
            vals = baseline_df[feat].dropna().values
            if len(vals) > 0:
                self.baseline_stats[feat] = {
                    "data": vals,
                    "quantiles": np.percentile(vals, np.linspace(0, 100, 11)),
                }

    def compute_psi(self, expected: np.ndarray, actual: np.ndarray, num_bins: int = 10) -> float:
        """Calculates Population Stability Index (PSI) between baseline and streaming batches."""
        if len(expected) == 0 or len(actual) == 0:
            return 0.0

        percentiles = np.linspace(0, 100, num_bins + 1)
        bin_edges = np.percentile(expected, percentiles)
        bin_edges[0] -= 1e-5
        bin_edges[-1] += 1e-5

        exp_counts = np.histogram(expected, bins=bin_edges)[0]
        act_counts = np.histogram(actual, bins=bin_edges)[0]

        # Convert to proportions with smoothing
        exp_pct = (exp_counts + 1e-4) / (len(expected) + 1e-4 * num_bins)
        act_pct = (act_counts + 1e-4) / (len(actual) + 1e-4 * num_bins)

        psi_val = np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct))
        return float(psi_val)

    def evaluate_drift(self, current_df: pd.DataFrame) -> Dict[str, Any]:
        """Runs PSI and 2-sample KS test across monitored features in current batch."""
        feature_reports = {}
        drift_flags = []

        for feat in self.monitored_features:
            if feat not in current_df.columns:
                continue

            current_vals = current_df[feat].dropna().values
            base_vals = self.baseline_stats.get(feat, {}).get("data", np.array([]))

            if len(current_vals) < 5 or len(base_vals) < 5:
                continue

            # 1. Compute PSI
            psi = self.compute_psi(base_vals, current_vals)

            # 2. Compute 2-Sample KS test
            ks_stat, p_val = ks_2samp(base_vals, current_vals)

            # Flag drift if PSI >= 0.25 or p-value < 0.01 with substantial KS statistic
            has_drift = bool(psi >= 0.25 or (p_val < 0.01 and ks_stat > 0.15))
            drift_flags.append(has_drift)

            feature_reports[feat] = {
                "psi": round(psi, 4),
                "ks_statistic": round(float(ks_stat), 4),
                "p_value": round(float(p_val), 4),
                "drift_status": "SIGNIFICANT_DRIFT" if psi >= 0.25 else ("MODERATE_DRIFT" if psi >= 0.10 else "STABLE"),
            }

        drift_percentage = float(np.mean(drift_flags)) if drift_flags else 0.0
        retrain_recommended = bool(drift_percentage >= 0.30)

        return {
            "overall_drift_status": "RETRAIN_REQUIRED" if retrain_recommended else "DATASET_STABLE",
            "drifting_features_ratio": round(drift_percentage, 2),
            "retrain_recommended": retrain_recommended,
            "feature_details": feature_reports,
        }
