"""Stage 3: Behavioral and Statistical Entropy Feature Engineering."""

import numpy as np
import pandas as pd
from scipy.stats import entropy
from src.utils.logger import get_logger

logger = get_logger("BehavioralFeatures")

class BehavioralFeatureExtractor:
    """Computes Shannon entropy of ports, fan-in/fan-out ratios, and traffic pattern profiles."""

    @staticmethod
    def extract(df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # 1. Destination Port Shannon Entropy per Source IP
        def compute_port_entropy(series: pd.Series) -> float:
            counts = series.value_counts()
            probs = counts / counts.sum()
            return float(entropy(probs, base=2)) if len(probs) > 1 else 0.0

        if "Src IP" in df.columns and "Dst Port" in df.columns:
            entropy_map = df.groupby("Src IP")["Dst Port"].apply(compute_port_entropy).to_dict()
            df["dst_port_entropy"] = df["Src IP"].map(entropy_map).fillna(0.0)
        else:
            df["dst_port_entropy"] = 0.0

        # 2. Fan-out degree: Distinct Destination IPs contacted by Source IP
        if "Src IP" in df.columns and "Dst IP" in df.columns:
            fan_out_map = df.groupby("Src IP")["Dst IP"].nunique().to_dict()
            df["fan_out_degree"] = df["Src IP"].map(fan_out_map).fillna(1.0)
        else:
            df["fan_out_degree"] = 1.0

        # 3. Fan-in degree: Distinct Source IPs contacting Destination IP
        if "Src IP" in df.columns and "Dst IP" in df.columns:
            fan_in_map = df.groupby("Dst IP")["Src IP"].nunique().to_dict()
            df["fan_in_degree"] = df["Dst IP"].map(fan_in_map).fillna(1.0)
        else:
            df["fan_in_degree"] = 1.0

        return df
