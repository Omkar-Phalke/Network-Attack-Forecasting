"""Stage 2: Data Cleaning and Standardization for CSE-CIC-IDS2018."""

from typing import Tuple, List, Optional
import numpy as np
import pandas as pd
from src.config import LABEL_TO_CLASS, RAW_NUMERIC_FEATURES
from src.utils.logger import get_logger

logger = get_logger("Cleaner")

class TrafficDataCleaner:
    """Handles column normalization, missing/infinite values, and label harmonization."""

    def __init__(self, clip_percentile: float = 99.9):
        self.clip_percentile = clip_percentile
        self.feature_medians_ = {}

    def clean(self, df: pd.DataFrame, is_training: bool = True) -> pd.DataFrame:
        """Cleans and standardizes raw network traffic DataFrame."""
        df = df.copy()

        # 1. Clean column names
        df.columns = df.columns.str.strip()

        # 2. Identify and standardize Label column
        label_col = None
        for col in ["Label", "label", "Class", "attack"]:
            if col in df.columns:
                label_col = col
                break

        if label_col:
            df["Label"] = df[label_col].astype(str).str.strip().str.lower().map(
                lambda x: LABEL_TO_CLASS.get(x, "Benign")
            )
            if label_col != "Label":
                df = df.drop(columns=[label_col])

        # 3. Clean numeric features
        for col in RAW_NUMERIC_FEATURES:
            if col not in df.columns:
                df[col] = 0.0
            else:
                # Convert to numeric
                df[col] = pd.to_numeric(df[col], errors="coerce")

                # Replace inf and -inf
                mask_inf = np.isinf(df[col])
                if mask_inf.any():
                    if is_training:
                        finite_vals = df[col][~mask_inf].dropna()
                        cap_val = float(np.percentile(finite_vals, self.clip_percentile)) if len(finite_vals) > 0 else 1e6
                        self.feature_medians_[f"{col}_cap"] = cap_val
                    else:
                        cap_val = self.feature_medians_.get(f"{col}_cap", 1e6)
                    df.loc[mask_inf, col] = cap_val

                # Replace NaNs with median
                if is_training:
                    median_val = float(df[col].median()) if not df[col].dropna().empty else 0.0
                    self.feature_medians_[col] = median_val
                else:
                    median_val = self.feature_medians_.get(col, 0.0)

                df[col] = df[col].fillna(median_val)

        logger.info(f"Cleaned dataset: {len(df)} rows, {len(df.columns)} columns.")
        return df
