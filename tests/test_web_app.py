"""Unit tests for Stage 7: Flask SOC Dashboard Routes and REST APIs."""

import unittest
import json
from app import app, soc_state

class TestSOCWebApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        soc_state.initialize()
        cls.client = app.test_client()

    def test_index_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"SIH26153", resp.data)
        self.assertIn(b"NetAttackForecast-AI", resp.data)

    def test_forecast_page(self):
        resp = self.client.get("/forecast")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Cyber Kill Chain", resp.data)

    def test_reports_page(self):
        resp = self.client.get("/reports")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"What-If Counterfactual", resp.data)

    def test_api_stream_next(self):
        resp = self.client.get("/api/stream/next?batch_size=3")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["processed_batch"]), 3)
        self.assertIn("latest_risk", data)
        self.assertIn("latest_forecast", data)

    def test_api_graph_current(self):
        resp = self.client.get("/api/graph/current")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

    def test_api_graph_forecast(self):
        resp = self.client.get("/api/graph/forecast")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("projected_nodes", data)
        self.assertIn("projected_edges", data)

    def test_api_whatif_post(self):
        payload = {
            "risk_score": 80.0,
            "kill_chain_stage": 4,
            "block_source_ip": True,
            "quarantine_host": True,
        }
        resp = self.client.post("/api/whatif", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertLess(data["simulated_risk_score"], 80.0)
        self.assertEqual(data["containment_status"], "CONTAINED")

    def test_api_explain(self):
        resp = self.client.get("/api/explain")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("top_features", data)

    def test_api_mitigation(self):
        resp = self.client.get("/api/mitigation?src_ip=203.0.113.19&dst_ip=192.168.10.20&port=80")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("firewall_rules", data)
        self.assertIn("ids_signatures", data)

    def test_api_export_csv(self):
        # Trigger an alert first by fetching a batch
        self.client.get("/api/stream/next?batch_size=5")
        resp = self.client.get("/api/export/csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)

if __name__ == "__main__":
    unittest.main()
