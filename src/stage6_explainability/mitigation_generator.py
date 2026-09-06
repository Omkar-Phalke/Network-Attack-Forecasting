"""Stage 6: Mitigation Rule Generator (iptables, nftables, Suricata)."""

from typing import Dict, Any, List
from src.utils.logger import get_logger

logger = get_logger("MitigationGenerator")

class MitigationRuleGenerator:
    """Generates ready-to-deploy firewall rules and IDS signatures for identified threats."""

    @staticmethod
    def generate_iptables_rules(src_ip: str, dst_ip: str, dst_port: int) -> List[str]:
        """Generates Linux iptables firewall rules to block or isolate traffic."""
        return [
            f"# 1. Immediately drop all inbound traffic from attacking IP",
            f"sudo iptables -I INPUT -s {src_ip} -j DROP",
            f"# 2. Drop forwarding to protect internal subnet",
            f"sudo iptables -I FORWARD -s {src_ip} -j DROP",
            f"# 3. Rate-limit target port {dst_port} to prevent resource exhaustion",
            f"sudo iptables -A INPUT -p tcp --dport {dst_port} -m connlimit --connlimit-above 50 -j REJECT",
        ]

    @staticmethod
    def generate_nftables_rules(src_ip: str, dst_ip: str, dst_port: int) -> List[str]:
        """Generates modern Linux nftables rules."""
        return [
            f"nft add element inet filter blacklisted_ips {{ {src_ip} }}",
            f"nft insert rule inet filter input ip saddr {src_ip} counter drop",
            f"nft insert rule inet filter forward ip saddr {src_ip} counter drop",
        ]

    @staticmethod
    def generate_suricata_signature(src_ip: str, dst_ip: str, dst_port: int, sid: int = 1000999) -> str:
        """Generates Suricata / Snort IDS rule for real-time alerting."""
        return (
            f'alert tcp {src_ip} any -> {dst_ip} {dst_port} '
            f'(msg:"SIH26153 - AI Forecasted Malicious Activity from {src_ip}"; '
            f'flags:S,12; threshold:type both, track by_src, count 20, seconds 60; '
            f'classtype:attempted-admin; sid:{sid}; rev:1;)'
        )

    @classmethod
    def generate_full_mitigation_package(
        cls,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        attack_type: str,
        forecasted_stage_name: str
    ) -> Dict[str, Any]:
        """Packages all mitigation rules and human analyst remediation instructions."""
        return {
            "attack_type": attack_type,
            "forecasted_stage": forecasted_stage_name,
            "threat_actor_ip": src_ip,
            "targeted_asset_ip": dst_ip,
            "targeted_port": dst_port,
            "firewall_rules": {
                "iptables": cls.generate_iptables_rules(src_ip, dst_ip, dst_port),
                "nftables": cls.generate_nftables_rules(src_ip, dst_ip, dst_port),
            },
            "ids_signatures": {
                "suricata": cls.generate_suricata_signature(src_ip, dst_ip, dst_port),
            },
            "analyst_checklist": [
                f"1. Verify no legitimate business service depends on external IP {src_ip}.",
                f"2. Check host {dst_ip} auth logs for successful logins around the incident time window.",
                f"3. Run memory and rootkit scan on {dst_ip} to verify whether Stage 3 Infiltration was achieved.",
                f"4. Apply iptables containment script on perimeter firewall.",
                f"5. Notify incident commander if target asset criticality >= 0.8.",
            ],
        }
