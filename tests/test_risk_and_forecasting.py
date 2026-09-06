"""Unit tests for Stage 5: Risk Assessment and Attack Graph Projection."""

import unittest
import networkx as nx
from src.stage5_risk_assessment.risk_engine import RiskScoringEngine
from src.stage5_risk_assessment.infiltration_exfil import InfiltrationExfilAnalyzer
from src.stage5_risk_assessment.attack_graph_projector import AttackGraphProjector

class TestStage5RiskAndForecasting(unittest.TestCase):

    def test_risk_scoring_engine(self):
        engine = RiskScoringEngine()
        res_crit = engine.calculate_score(attack_prob=0.95, kill_chain_stage=6, asset_criticality=0.9, anomaly_score=0.8)
        self.assertGreaterEqual(res_crit["risk_score"], 80.0)
        self.assertEqual(res_crit["risk_level"], "Critical")

        res_low = engine.calculate_score(attack_prob=0.05, kill_chain_stage=0, asset_criticality=0.3, anomaly_score=0.1)
        self.assertLess(res_low["risk_score"], 35.0)
        self.assertEqual(res_low["risk_level"], "Low")

    def test_infiltration_exfil_analyzer(self):
        flow = {
            "cross_subnet_flag": 1,
            "Dst Port": 3389,
            "dst_asset_criticality": 0.9,
            "TotLen Fwd Pkts": 60000,
            "payload_asymmetry_ratio": 2.5,
        }
        infil = InfiltrationExfilAnalyzer.assess_infiltration(flow)
        self.assertTrue(infil["is_infiltration_alert"])

        exfil = InfiltrationExfilAnalyzer.assess_exfiltration(flow)
        self.assertTrue(exfil["is_exfiltration_alert"])

    def test_attack_graph_projector(self):
        g = nx.DiGraph()
        projector = AttackGraphProjector(g)
        projected = projector.project_future_attack_graph(
            compromised_ips=["203.0.113.19"],
            forecasted_stage=3,
        )
        self.assertGreater(len(projected["projected_nodes"]), 0)
        self.assertGreater(len(projected["projected_edges"]), 0)

if __name__ == "__main__":
    unittest.main()
