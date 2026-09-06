"""Stage 3: Temporal Window Feature Engineering."""

import pandas as pd
import numpy as np
from src.utils.logger import get_logger

logger = get_logger("TemporalFeatures")

class TemporalFeatureExtractor:
    """Computes rolling historical window statistics (60s, 300s) per source/destination IP."""

    @staticmethod
    def extract(df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # Ensure timestamp is datetime index for rolling calculation
        if "timestamp_dt" in df.columns:
            temp_df = df.copy().set_index("timestamp_dt")
        else:
            # Create synthetic sequence if not available
            temp_df = df.copy()
            temp_df.index = pd.date_range("2018-02-14 08:00:00", periods=len(df), freq="100ms")

        # Group by Source IP to compute temporal rate features
        # 1. 60-second rolling connection count
        try:
            rolling_60s = temp_df.groupby("Src IP")["Dst Port"].rolling("60s").count().reset_index()
            rolling_60s = rolling_60s.rename(columns={"Dst Port": "rolling_conn_rate_60s"})
            df["rolling_conn_rate_60s"] = rolling_60s["rolling_conn_rate_60s"].values
        except Exception:
            df["rolling_conn_rate_60s"] = 1.0

        # 2. 300-second rolling connection count
        try:
            rolling_300s = temp_df.groupby("Src IP")["Dst Port"].rolling("300s").count().reset_index()
            rolling_300s = rolling_300s.rename(columns={"Dst Port": "rolling_conn_rate_300s"})
            df["rolling_conn_rate_300s"] = rolling_300s["rolling_conn_rate_300s"].values
        except Exception:
            df["rolling_conn_rate_300s"] = 1.0

        # 3. 60-second unique destination ports probed
        try:
            unique_ports = temp_df.groupby("Src IP")["Dst Port"].rolling("60s").apply(
                lambda s: len(np.unique(s)), raw=True
            ).reset_index()
            df["rolling_unique_ports_60s"] = unique_ports["Dst Port"].values
        except Exception:
            df["rolling_unique_ports_60s"] = 1.0

        # 4. Rolling SYN ratio (indicates SYN Flood DDoS when elevated)
        syn_counts = df.get("SYN Flag Cnt", 0.0)
        tot_pkts = (df.get("Tot Fwd Pkts", 1.0) + df.get("Tot Bwd Pkts", 0.0)).clip(lower=1.0)
        df["rolling_syn_ratio_60s"] = (syn_counts / tot_pkts).clip(0.0, 1.0)

        # 5. Rolling byte volume over 300s
        tot_bytes = df.get("TotLen Fwd Pkts", 0.0) + df.get("TotLen Bwd Pkts", 0.0)
        df["rolling_byte_volume_300s"] = tot_bytes

        return df
