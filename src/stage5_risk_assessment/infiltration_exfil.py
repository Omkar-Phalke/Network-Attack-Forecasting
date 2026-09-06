"""Stage 5: Infiltration (Internal Entry) & Exfiltration (Data Leakage) Analytics."""

from typing import Dict, Any, List
import pandas as pd
from src.utils.logger import get_logger

logger = get_logger("InfiltrationExfil")

class InfiltrationExfilAnalyzer:
    """Specialized analyzer for Internal Entry (Infiltration) and Data Leakage (Exfiltration)."""

    @staticmethod
    def assess_infiltration(flow_record: Dict[str, Any]) -> Dict[str, Any]:
        """Assesses likelihood of perimeter penetration into internal network zones."""
        cross_subnet = flow_record.get("cross_subnet_flag", 0)
        dst_port = int(flow_record.get("Dst Port", 0))
        dst_criticality = float(flow_record.get("dst_asset_criticality", 0.35))
        fwd_bytes = float(flow_record.get("TotLen Fwd Pkts", 0.0))

        # Risk signals: external source contacting sensitive internal management ports (RDP, SMB, SSH, DB)
        is_sensitive_port = dst_port in [22, 445, 3389, 1433, 3306, 5432]
        score = 0.0
        signals = []

        if cross_subnet:
            score += 30.0
            signals.append("Perimeter crossing detected from external ingress to internal subnet")
        if is_sensitive_port:
            score += 40.0
            signals.append(f"Direct targeting of administrative/internal port {dst_port}")
        if dst_criticality >= 0.8:
            score += 20.0
            signals.append(f"High-value target asset criticality ({dst_criticality})")
        if fwd_bytes > 5000:
            score += 10.0
            signals.append(f"Substantial forward payload transmission ({int(fwd_bytes)} bytes)")

        score = min(100.0, score)
        return {
            "infiltration_risk": round(score, 1),
            "is_infiltration_alert": score >= 60.0,
            "detected_signals": signals,
        }

    @staticmethod
    def assess_exfiltration(flow_record: Dict[str, Any]) -> Dict[str, Any]:
        """Assesses likelihood of unauthorized outbound data leakage."""
        asym_ratio = float(flow_record.get("payload_asymmetry_ratio", 0.0))
        fwd_bytes = float(flow_record.get("TotLen Fwd Pkts", 0.0))
        dst_port = int(flow_record.get("Dst Port", 0))

        score = 0.0
        signals = []

        # Strongly positive asymmetry indicates heavy forward transmission with negligible response
        if asym_ratio > 1.5 and fwd_bytes > 50000:
            score += 50.0
            signals.append(f"Extreme payload asymmetry ({asym_ratio:.2f}) with {int(fwd_bytes)} egress bytes")
        elif asym_ratio > 1.0 and fwd_bytes > 10000:
            score += 30.0
            signals.append(f"Elevated outbound byte volume ({int(fwd_bytes)} bytes)")

        # Non-standard egress ports
        if dst_port not in [80, 443] and fwd_bytes > 10000:
            score += 30.0
            signals.append(f"High-volume data egress across non-standard port {dst_port}")

        score = min(100.0, score)
        return {
            "exfiltration_risk": round(score, 1),
            "is_exfiltration_alert": score >= 50.0,
            "detected_signals": signals,
        }
