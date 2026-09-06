"""Unit tests for Stage 2: Preprocessing and Normalization."""

import unittest
import numpy as np
import pandas as pd
from src.stage2_preprocessing.cleaner import TrafficDataCleaner
from src.stage2_preprocessing.normalizer import TrafficNormalizer
from src.stage2_preprocessing.enricher import TrafficEnricher

class TestStage2Preprocessing(unittest.TestCase):

    def setUp(self):
        self.raw_df = pd.DataFrame({
            " Destination Port ": [80, 22, 443],
            "Flow Duration": [1000, np.inf, np.nan],
            "Flow Byts/s": [500.0, np.inf, 100.0],
            "Label": ["Benign", "FTP-BruteForce", "dos attacks-hulk"],
            "Timestamp": ["14/02/2018 08:30:00", "14/02/2018 08:31:00", "14/02/2018 08:32:00"],
            "Src IP": ["192.168.10.50", "203.0.113.19", "192.168.10.55"],
            "Dst IP": ["192.168.10.20", "192.168.10.5", "198.51.100.42"],
        })

    def test_cleaner_handles_inf_and_labels(self):
        cleaner = TrafficDataCleaner()
        cleaned = cleaner.clean(self.raw_df, is_training=True)
        self.assertFalse(np.isinf(cleaned["Flow Duration"]).any())
        self.assertFalse(cleaned["Flow Duration"].isna().any())
        self.assertEqual(cleaned["Label"].iloc[1], "BruteForce")
        self.assertEqual(cleaned["Label"].iloc[2], "DoS_DDoS")

    def test_normalizer_standardizes_timestamps(self):
        cleaner = TrafficDataCleaner()
        cleaned = cleaner.clean(self.raw_df)
        norm = TrafficNormalizer(feature_cols=["Flow Duration", "Flow Byts/s"])
        normalized = norm.standardize_timestamps(cleaned)
        self.assertIn("timestamp_epoch", normalized.columns)
        self.assertIn("timestamp_iso", normalized.columns)

    def test_enricher_subnets_and_quality(self):
        cleaner = TrafficDataCleaner()
        cleaned = cleaner.clean(self.raw_df)
        enricher = TrafficEnricher()
        enriched = enricher.enrich(cleaned)
        self.assertIn("service_name", enriched.columns)
        self.assertIn("cross_subnet_flag", enriched.columns)
        qa = enricher.validate_quality(enriched)
        self.assertIn("quality_status", qa)

if __name__ == "__main__":
    unittest.main()
