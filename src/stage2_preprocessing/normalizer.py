"""Stage 2: Feature Normalizer and Timestamp Standardizer."""

from typing import List, Optional
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from src.utils.logger import get_logger

logger = get_logger("Normalizer")

class TrafficNormalizer:
    """Standardizes timestamps and applies robust scaling to heavy-tailed flow metrics."""

    def __init__(self, feature_cols: Optional[List[str]] = None):
        self.feature_cols = feature_cols or []
        self.scaler = RobustScaler(quantile_range=(5.0, 95.0))
        self.is_fitted = False

    def standardize_timestamps(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardizes timestamps into numeric Unix epoch seconds and ISO string."""
        df = df.copy()
        if "Timestamp" in df.columns:
            # Try parsing multiple date formats present in CSE-CIC-IDS2018
            parsed_dt = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
            mask_unparsed = parsed_dt.isna()
            if mask_unparsed.any():
                # Fallback to generic parsing
                parsed_dt[mask_unparsed] = pd.to_datetime(df.loc[mask_unparsed, "Timestamp"], errors="coerce")

            # Fallback for still unparsed: sequential synthetic timestamps
            if parsed_dt.isna().all():
                start_time = pd.Timestamp("2018-02-14 08:00:00")
                parsed_dt = pd.date_range(start=start_time, periods=len(df), freq="100ms")

            df["timestamp_dt"] = parsed_dt
            df["timestamp_epoch"] = (parsed_dt.astype("int64") // 10**9).astype(float)
            df["timestamp_iso"] = parsed_dt.dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            # Generate sequential timestamps if column missing
            start_time = pd.Timestamp("2018-02-14 08:00:00")
            parsed_dt = pd.date_range(start=start_time, periods=len(df), freq="100ms")
            df["timestamp_dt"] = parsed_dt
            df["timestamp_epoch"] = (parsed_dt.astype("int64") // 10**9).astype(float)
            df["timestamp_iso"] = parsed_dt.dt.strftime("%Y-%m-%d %H:%M:%S")

        # Chronological sort
        df = df.sort_values("timestamp_epoch").reset_index(drop=True)
        return df

    def fit(self, df: pd.DataFrame):
        """Fits the RobustScaler on specified numeric features."""
        cols_to_scale = [c for c in self.feature_cols if c in df.columns]
        if cols_to_scale:
            self.scaler.fit(df[cols_to_scale].values)
            self.is_fitted = True
            logger.info(f"Fitted RobustScaler on {len(cols_to_scale)} numerical columns.")

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Transforms numeric features using the fitted scaler."""
        df = df.copy()
        cols_to_scale = [c for c in self.feature_cols if c in df.columns]
        if self.is_fitted and cols_to_scale:
            scaled_values = self.scaler.transform(df[cols_to_scale].values)
            # Add scaled versions with '_scaled' suffix
            for i, col in enumerate(cols_to_scale):
                df[f"{col}_scaled"] = scaled_values[:, i]
        return df

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fits and transforms in a single call."""
        self.fit(df)
        return self.transform(df)
