"""Stage 1: Zeek & PCAP Log Extractor and Normalizer."""

import json
from typing import Dict, Any, List
import pandas as pd
from src.utils.logger import get_logger

logger = get_logger("ZeekParser")

class ZeekLogParser:
    """Parses Zeek conn.log / JSON / PCAP summary records into standardized flow format."""

    @staticmethod
    def parse_zeek_json_line(line: str) -> Dict[str, Any]:
        """Parses a single JSON line from Zeek JSON-formatted conn.log."""
        record = json.loads(line)
        # Mapping Zeek fields to CIC-IDS equivalent flow features
        return {
            "Timestamp": record.get("ts", 0),
            "Src IP": record.get("id.orig_h", "0.0.0.0"),
            "Src Port": int(record.get("id.orig_p", 0)),
            "Dst IP": record.get("id.resp_h", "0.0.0.0"),
            "Dst Port": int(record.get("id.resp_p", 0)),
            "Protocol": 6 if record.get("proto") == "tcp" else (17 if record.get("proto") == "udp" else 1),
            "Flow Duration": int(float(record.get("duration", 0.0)) * 1e6),
            "TotLen Fwd Pkts": int(record.get("orig_bytes", 0) or 0),
            "TotLen Bwd Pkts": int(record.get("resp_bytes", 0) or 0),
            "Tot Fwd Pkts": int(record.get("orig_pkts", 1) or 1),
            "Tot Bwd Pkts": int(record.get("resp_pkts", 0) or 0),
            "Label": "Benign",
        }

    @classmethod
    def convert_zeek_records(cls, records: List[Dict[str, Any]]) -> pd.DataFrame:
        """Converts a list of parsed Zeek records into a standard DataFrame."""
        df = pd.DataFrame(records)
        logger.info(f"Converted {len(df)} Zeek records to standard flow DataFrame.")
        return df
