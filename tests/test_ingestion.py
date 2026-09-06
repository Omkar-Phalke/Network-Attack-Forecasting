"""Unit tests for Stage 1: Data Ingestion and Telemetry Streaming."""

import unittest
from pathlib import Path
import pandas as pd
from src.stage1_ingestion.csv_loader import CICIDS2018Loader
from src.stage1_ingestion.zeek_pcap_parser import ZeekLogParser
from src.stage1_ingestion.stream_simulator import NetworkStreamSimulator
from src.config import SAMPLE_DATA_DIR

class TestStage1Ingestion(unittest.TestCase):

    def setUp(self):
        self.sample_csv = SAMPLE_DATA_DIR / "cicids2018_sample.csv"
        self.assertTrue(self.sample_csv.exists(), "Sample benchmark CSV must exist.")

    def test_csv_loader_load_sample(self):
        loader = CICIDS2018Loader(self.sample_csv)
        df = loader.load_sample(n_rows=500)
        self.assertGreater(len(df), 0)
        self.assertIn("Dst Port", df.columns)
        self.assertIn("Label", df.columns)

    def test_zeek_parser(self):
        zeek_line = '{"ts": 1518595200.0, "id.orig_h": "192.168.10.50", "id.orig_p": 49152, "id.resp_h": "192.168.10.20", "id.resp_p": 80, "proto": "tcp", "duration": 0.05, "orig_bytes": 450, "resp_bytes": 1200}'
        rec = ZeekLogParser.parse_zeek_json_line(zeek_line)
        self.assertEqual(rec["Src IP"], "192.168.10.50")
        self.assertEqual(rec["Dst Port"], 80)
        self.assertEqual(rec["Protocol"], 6)

    def test_stream_simulator(self):
        dummy_df = pd.DataFrame({
            "Timestamp": ["14/02/2018 08:00:01", "14/02/2018 08:00:02"],
            "Dst Port": [80, 443],
            "Label": ["Benign", "Benign"],
        })
        sim = NetworkStreamSimulator(dummy_df)
        batch = sim.get_next_batch(batch_size=1)
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch.iloc[0]["Dst Port"], 80)

if __name__ == "__main__":
    unittest.main()
