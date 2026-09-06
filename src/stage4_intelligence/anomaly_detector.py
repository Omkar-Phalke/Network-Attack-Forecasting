"""Stage 4: Unsupervised Anomaly Detection using Isolation Forest."""

from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
from src.config import ALL_MODEL_FEATURES, MODELS_DIR
from src.utils.logger import get_logger

logger = get_logger("AnomalyDetector")

class AnomalyDetector:
    """Unsupervised Isolation Forest model for zero-day and outlier intrusion detection."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.feature_names = []
        self.is_fitted = False

    def fit(self, df: pd.DataFrame, feature_cols: list = None):
        """Trains Isolation Forest on feature matrix."""
        self.feature_names = feature_cols or [c for c in ALL_MODEL_FEATURES if c in df.columns]
        X = df[self.feature_names].values
        self.model.fit(X)
        self.is_fitted = True
        logger.info(f"Fitted AnomalyDetector on {X.shape[0]} samples with {X.shape[1]} features.")

    def predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predicts anomaly status (-1 for anomaly, 1 for normal) and continuous anomaly score."""
        if not self.is_fitted:
            raise ValueError("AnomalyDetector must be fitted before predict.")
        X = df[self.feature_names].values
        preds = self.model.predict(X)
        # raw decision function: negative values indicate anomalies
        raw_scores = self.model.decision_function(X)
        # normalize anomaly score to [0.0, 1.0] where 1.0 is most anomalous
        anomaly_scores = 1.0 / (1.0 + np.exp(raw_scores * 5.0))
        is_anomaly = (preds == -1).astype(int)
        return is_anomaly, anomaly_scores

    def save(self, filepath=None):
        path = filepath or (MODELS_DIR / "anomaly_detector.joblib")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "features": self.feature_names}, path)
        logger.info(f"Saved AnomalyDetector to {path}")

    def load(self, filepath=None):
        path = filepath or (MODELS_DIR / "anomaly_detector.joblib")
        data = joblib.load(path)
        self.model = data["model"]
        self.feature_names = data["features"]
        self.is_fitted = True
        logger.info(f"Loaded AnomalyDetector from {path}")
