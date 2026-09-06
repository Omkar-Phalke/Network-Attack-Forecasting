"""Unit tests for Stage 4: AI/ML Models and Attack Forecaster."""

import unittest
import pandas as pd
import numpy as np
from src.stage4_intelligence.anomaly_detector import AnomalyDetector
from src.stage4_intelligence.attack_classifier import AttackClassifier
from src.stage4_intelligence.kill_chain_estimator import KillChainEstimator
from src.stage4_intelligence.attack_forecaster import AttackForecaster
from src.stage4_intelligence.drift_detector import DriftDetector
from src.config import SAMPLE_DATA_DIR

class TestStage4Models(unittest.TestCase):

    def setUp(self):
        sample_csv = SAMPLE_DATA_DIR / "cicids2018_sample.csv"
        self.df = pd.read_csv(sample_csv).head(500)

    def test_anomaly_detector(self):
        detector = AnomalyDetector(contamination=0.1)
        detector.fit(self.df)
        is_anom, scores = detector.predict(self.df)
        self.assertEqual(len(is_anom), len(self.df))
        self.assertTrue(all(0.0 <= s <= 1.0 for s in scores))

    def test_attack_classifier(self):
        clf = AttackClassifier(n_estimators=10)
        clf.fit(self.df, target_col="Label")
        preds, probs = clf.predict(self.df)
        self.assertEqual(len(preds), len(self.df))
        importances = clf.get_feature_importances(top_n=5)
        self.assertGreater(len(importances), 0)

    def test_kill_chain_and_forecaster(self):
        estimator = KillChainEstimator()
        stage = estimator.estimate_stage("Reconnaissance")
        self.assertEqual(stage, 1)

        forecaster = AttackForecaster()
        forecast = forecaster.forecast_next_stage(stage)
        self.assertIn("predicted_next_stage", forecast)
        self.assertGreater(forecast["transition_probability"], 0.0)
        self.assertGreater(forecast["estimated_time_to_impact_minutes"], 0.0)

    def test_drift_detector(self):
        base = self.df.iloc[:250]
        curr = self.df.iloc[250:]
        detector = DriftDetector(base, monitored_features=["Flow Duration", "Flow Byts/s"])
        drift_res = detector.evaluate_drift(curr)
        self.assertIn("overall_drift_status", drift_res)

if __name__ == "__main__":
    unittest.main()
