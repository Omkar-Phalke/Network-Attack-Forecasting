"""Unit tests for Stage 3: Feature Engineering and Dynamic Host Graph."""

import unittest
import pandas as pd
import numpy as np
from src.stage3_feature_engineering.flow_features import FlowFeatureExtractor
from src.stage3_feature_engineering.temporal_features import TemporalFeatureExtractor
from src.stage3_feature_engineering.behavioral_features import BehavioralFeatureExtractor
from src.stage3_feature_engineering.graph_builder import HostGraphBuilder

class TestStage3FeatureEngineering(unittest.TestCase):

    def setUp(self):
        self.df = pd.DataFrame({
            "Src IP": ["192.168.10.50", "192.168.10.50", "203.0.113.19"],
            "Dst IP": ["192.168.10.20", "192.168.10.5", "192.168.10.20"],
            "Dst Port": [80, 22, 80],
            "TotLen Fwd Pkts": [500, 1500, 100],
            "TotLen Bwd Pkts": [1200, 200, 50],
            "Tot Fwd Pkts": [10, 20, 2],
            "Tot Bwd Pkts": [15, 2, 1],
            "SYN Flag Cnt": [1, 1, 1],
            "Timestamp": ["14/02/2018 08:00:01", "14/02/2018 08:00:02", "14/02/2018 08:00:03"],
            "Label": ["Benign", "BruteForce", "Reconnaissance"],
        })

    def test_flow_features(self):
        res = FlowFeatureExtractor.extract(self.df)
        self.assertIn("payload_asymmetry_ratio", res.columns)

    def test_temporal_features(self):
        res = TemporalFeatureExtractor.extract(self.df)
        self.assertIn("rolling_conn_rate_60s", res.columns)
        self.assertIn("rolling_syn_ratio_60s", res.columns)

    def test_behavioral_features(self):
        res = BehavioralFeatureExtractor.extract(self.df)
        self.assertIn("dst_port_entropy", res.columns)
        self.assertIn("fan_out_degree", res.columns)

    def test_graph_builder(self):
        builder = HostGraphBuilder()
        graph = builder.build_from_dataframe(self.df)
        self.assertGreater(len(graph.nodes), 0)
        self.assertGreater(len(graph.edges), 0)
        vis_json = builder.to_visualization_json()
        self.assertIn("nodes", vis_json)
        self.assertIn("edges", vis_json)

if __name__ == "__main__":
    unittest.main()
