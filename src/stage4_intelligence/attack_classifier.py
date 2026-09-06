"""Stage 4: Supervised Multi-Class Attack Classifier."""

from typing import Tuple, Dict, Any, List, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
from src.config import ALL_MODEL_FEATURES, ATTACK_CLASSES, MODELS_DIR
from src.utils.logger import get_logger

logger = get_logger("AttackClassifier")

class AttackClassifier:
    """Supervised multi-class ensemble for network attack classification."""

    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=16,
            min_samples_split=4,
            class_weight="balanced_subsample",
            random_state=random_state,
            n_jobs=-1,
        )
        self.feature_names = []
        self.classes_ = []
        self.is_fitted = False

    def fit(self, df: pd.DataFrame, target_col: str = "Label", feature_cols: list = None):
        """Trains multi-class classifier on engineered feature set."""
        self.feature_names = feature_cols or [c for c in ALL_MODEL_FEATURES if c in df.columns]
        X = df[self.feature_names].values
        y = df[target_col].astype(str).values

        self.model.fit(X, y)
        self.classes_ = list(self.model.classes_)
        self.is_fitted = True
        logger.info(f"Trained AttackClassifier on {X.shape[0]} records across classes: {self.classes_}")

    def predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Returns predicted class labels and probability distribution over attack classes."""
        if not self.is_fitted:
            raise ValueError("AttackClassifier must be fitted before predict.")
        X = df[self.feature_names].values
        preds = self.model.predict(X)
        probs = self.model.predict_proba(X)
        return preds, probs

    def get_feature_importances(self, top_n: int = 20) -> List[Dict[str, Any]]:
        """Returns top feature importances sorted by Gini impurity reduction."""
        if not self.is_fitted:
            return []
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1][:top_n]
        return [
            {"feature": self.feature_names[i], "importance": round(float(importances[i]), 4)}
            for i in indices
        ]

    def save(self, filepath=None):
        path = filepath or (MODELS_DIR / "attack_classifier.joblib")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "features": self.feature_names,
            "classes": self.classes_
        }, path)
        logger.info(f"Saved AttackClassifier to {path}")

    def load(self, filepath=None):
        path = filepath or (MODELS_DIR / "attack_classifier.joblib")
        data = joblib.load(path)
        self.model = data["model"]
        self.feature_names = data["features"]
        self.classes_ = data["classes"]
        self.is_fitted = True
        logger.info(f"Loaded AttackClassifier from {path}")
