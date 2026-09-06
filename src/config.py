"""Central configuration for SIH26153: AI-Based Network Attack Forecasting.
Defines paths, feature definitions, attack mappings, kill chain stages,
and scoring weights.
"""

from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLE_DATA_DIR = DATA_DIR / "sample"
MODELS_DIR = BASE_DIR / "models"
DOCS_DIR = BASE_DIR / "docs"

# Raw Features in CSE-CIC-IDS2018 (Canonical Subset & Critical Features)
RAW_NUMERIC_FEATURES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Engineered Features for Attack Forecasting
ENGINEERED_FEATURES = [
    "rolling_conn_rate_60s",
    "rolling_conn_rate_300s",
    "rolling_unique_ports_60s",
    "rolling_syn_ratio_60s",
    "rolling_byte_volume_300s",
    "dst_port_entropy",
    "payload_asymmetry_ratio",
    "fan_out_degree",
    "fan_in_degree",
    "host_in_degree_centrality",
    "host_out_degree_centrality",
    "host_pagerank",
    "cross_subnet_flag",
]

# All features fed into models
ALL_MODEL_FEATURES = RAW_NUMERIC_FEATURES + ENGINEERED_FEATURES

# Attack Class Mapping
ATTACK_CLASSES = [
    "Benign",
    "Reconnaissance",
    "BruteForce",
    "Infiltration",
    "LateralMovement",
    "Botnet_C2",
    "DoS_DDoS",
]

LABEL_TO_CLASS = {
    "benign": "Benign",
    "portscan": "Reconnaissance",
    "reconnaissance": "Reconnaissance",
    "ftp-bruteforce": "BruteForce",
    "ssh-bruteforce": "BruteForce",
    "bruteforce": "BruteForce",
    "dos attacks-goldeneye": "DoS_DDoS",
    "dos attacks-slowloris": "DoS_DDoS",
    "dos attacks-slowhttptest": "DoS_DDoS",
    "dos attacks-hulk": "DoS_DDoS",
    "ddos attacks-loic-http": "DoS_DDoS",
    "ddos attacks-hoic": "DoS_DDoS",
    "dos": "DoS_DDoS",
    "ddos": "DoS_DDoS",
    "bot": "Botnet_C2",
    "botnet": "Botnet_C2",
    "c2": "Botnet_C2",
    "infiltration": "Infiltration",
    "lateralmovement": "LateralMovement",
    "web attacks-xss": "BruteForce",
    "web attacks-sql injection": "Infiltration",
}

# Cyber Kill Chain Stages & Weights for Risk Scoring
KILL_CHAIN_STAGES = {
    0: {"name": "Benign / Normal", "weight": 0.0, "severity": "Low"},
    1: {"name": "Reconnaissance & Scanning", "weight": 15.0, "severity": "Low"},
    2: {"name": "Initial Access & Brute Force", "weight": 40.0, "severity": "Medium"},
    3: {"name": "Infiltration & Exploitation", "weight": 70.0, "severity": "High"},
    4: {"name": "Lateral Movement & Internal Pivot", "weight": 85.0, "severity": "High"},
    5: {"name": "Command & Control (C2)", "weight": 90.0, "severity": "Critical"},
    6: {"name": "Actions on Objectives (Exfil / DoS)", "weight": 100.0, "severity": "Critical"},
}

# Subnet Definitions & Critical Asset Roles
INTERNAL_SUBNETS = ["192.168.10.", "192.168.1.", "10.0."]
CRITICAL_ASSETS = {
    "192.168.10.1": {"name": "Primary Gateway / Firewall", "criticality": 0.90, "role": "Gateway"},
    "192.168.10.5": {"name": "Domain Controller & Active Directory", "criticality": 1.00, "role": "Identity/Auth"},
    "192.168.10.15": {"name": "Core Financial Database Server", "criticality": 0.95, "role": "Database"},
    "192.168.10.20": {"name": "Production Web Application Server", "criticality": 0.85, "role": "Web DMZ"},
    "192.168.10.50": {"name": "SOC Analyst Workstation", "criticality": 0.60, "role": "Workstation"},
    "192.168.10.55": {"name": "Engineering Workstation A", "criticality": 0.40, "role": "Workstation"},
    "192.168.10.56": {"name": "Engineering Workstation B", "criticality": 0.40, "role": "Workstation"},
}
DEFAULT_CRITICALITY = 0.35

# Risk Thresholds
RISK_LEVELS = {
    "Critical": 80.0,
    "High": 60.0,
    "Medium": 35.0,
    "Low": 0.0,
}
