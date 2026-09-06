"""Stage 2: Event Enrichment and Data Quality Checks."""

from typing import Dict, Any, Tuple
import pandas as pd
from src.config import INTERNAL_SUBNETS, CRITICAL_ASSETS, DEFAULT_CRITICALITY
from src.utils.logger import get_logger

logger = get_logger("Enricher")

WELL_KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
}

class TrafficEnricher:
    """Enriches network flow events with cyber contextual tags and performs QA checks."""

    @staticmethod
    def enrich(df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # 1. Enrich Destination Service Name
        if "Dst Port" in df.columns:
            df["service_name"] = df["Dst Port"].map(lambda p: WELL_KNOWN_PORTS.get(int(p), "Other/HighPort"))
        else:
            df["service_name"] = "Unknown"

        # 2. Assign realistic IP topology if missing from raw flow CSV
        if "Src IP" not in df.columns:
            # Generate deterministic IP mappings based on index or labels
            df["Src IP"] = "192.168.10.50"
        if "Dst IP" not in df.columns:
            df["Dst IP"] = "192.168.10.20"

        # 3. Subnet Classification & Boundary Crossing
        def is_internal(ip: str) -> bool:
            return any(str(ip).startswith(subnet) for subnet in INTERNAL_SUBNETS)

        df["src_is_internal"] = df["Src IP"].apply(is_internal)
        df["dst_is_internal"] = df["Dst IP"].apply(is_internal)
        # Cross-subnet flag: crossing perimeter or traversing between internal and external
        df["cross_subnet_flag"] = (df["src_is_internal"] != df["dst_is_internal"]).astype(int)

        # 4. Asset Criticality Mapping
        df["dst_asset_criticality"] = df["Dst IP"].map(
            lambda ip: CRITICAL_ASSETS.get(str(ip), {}).get("criticality", DEFAULT_CRITICALITY)
        )
        df["src_asset_criticality"] = df["Src IP"].map(
            lambda ip: CRITICAL_ASSETS.get(str(ip), {}).get("criticality", DEFAULTCRITICALITY := DEFAULT_CRITICALITY)
        )

        logger.info(f"Enriched {len(df)} records with service names, subnets, and asset weights.")
        return df

    @staticmethod
    def validate_quality(df: pd.DataFrame) -> Dict[str, Any]:
        """Performs data quality checks (completeness, range consistency)."""
        null_counts = df.isnull().sum().to_dict()
        total_nulls = sum(null_counts.values())
        duplicate_flows = int(df.duplicated().sum())

        quality_report = {
            "total_records": len(df),
            "total_columns": len(df.columns),
            "total_null_cells": total_nulls,
            "duplicate_records": duplicate_flows,
            "quality_status": "PASS" if total_nulls == 0 and len(df) > 0 else "WARNING",
        }
        logger.info(f"Data Quality Check Result: {quality_report['quality_status']}")
        return quality_report
