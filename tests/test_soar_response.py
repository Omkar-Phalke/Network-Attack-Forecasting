"""Unit tests for Stage 6: Explainability and SOAR Response."""

import unittest
from src.stage6_explainability.explainer import ThreatExplainer
from src.stage6_explainability.what_if_simulator import WhatIfSimulator
from src.stage6_explainability.response_engine import AutomatedResponseEngine
from src.stage6_explainability.mitigation_generator import MitigationRuleGenerator

class TestStage6SOARResponse(unittest.TestCase):

    def test_threat_explainer(self):
        explainer = ThreatExplainer()
        flow = {
            "rolling_conn_rate_60s": 40.0,
            "dst_port_entropy": 3.2,
            "rolling_syn_ratio_60s": 0.9,
            "payload_asymmetry_ratio": 1.5,
        }
        res = explainer.explain_flow(flow)
        self.assertGreater(len(res["top_features"]), 0)
        self.assertIn("summary", res)

    def test_what_if_simulator(self):
        sim = WhatIfSimulator.simulate_intervention(
            pre_risk_score=75.0,
            pre_kill_chain_stage=3,
            block_source_ip=True,
            quarantine_host=True,
        )
        self.assertLess(sim["simulated_risk_score"], 75.0)
        self.assertLess(sim["delta_risk"], 0.0)
        self.assertEqual(sim["containment_status"], "CONTAINED")

    def test_automated_response_engine(self):
        res = AutomatedResponseEngine.execute_policy(
            src_ip="203.0.113.19",
            dst_ip="192.168.10.20",
            risk_score=85.0,
            risk_level="Critical",
            predicted_stage=4,
            predicted_stage_name="Lateral Movement",
        )
        self.assertEqual(res["policy_action_type"], "ACTIVE_CONTAINMENT")
        self.assertGreater(len(res["actions_executed"]), 0)

    def test_mitigation_generator(self):
        pkg = MitigationRuleGenerator.generate_full_mitigation_package(
            src_ip="203.0.113.19",
            dst_ip="192.168.10.20",
            dst_port=80,
            attack_type="DoS_DDoS",
            forecasted_stage_name="Actions on Objectives",
        )
        self.assertIn("iptables", pkg["firewall_rules"])
        self.assertIn("suricata", pkg["ids_signatures"])
        self.assertGreater(len(pkg["analyst_checklist"]), 0)

if __name__ == "__main__":
    unittest.main()
