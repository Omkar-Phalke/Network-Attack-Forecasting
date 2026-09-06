"""Stage 3: Flow-level Feature Engineering."""

import numpy as np
import pandas as pd
from src.utils.logger import get_logger

logger = get_logger("FlowFeatures")

class FlowFeatureExtractor:
    """Extracts derived flow-level indicators (packet size asymmetry, header ratios)."""

    @staticmethod
    def extract(df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # Payload Asymmetry Ratio (Log ratio of forward to backward bytes)
        fwd_bytes = df.get("TotLen Fwd Pkts", 0.0)
        bwd_bytes = df.get("TotLen Bwd Pkts", 0.0)
        df["payload_asymmetry_ratio"] = np.log10((fwd_bytes + 1.0) / (bwd_bytes + 1.0))

        # Packet count ratio
        fwd_pkts = df.get("Tot Fwd Pkts", 1.0).clip(lower=1.0)
        bwd_pkts = df.get("Tot Bwd Pkts", 0.0)
        df["pkt_count_ratio"] = fwd_pkts / (bwd_pkts + 1.0)

        # Header to payload ratio
        fwd_hdr_len = df.get("Fwd Header Len", 0.0)
        df["fwd_header_payload_ratio"] = fwd_hdr_len / (fwd_bytes + 1.0)

        return df
