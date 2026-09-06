"""Kaggle Dataset Downloader and Benchmark Sample Generator for CSE-CIC-IDS2018."""

import os
import sys
import shutil
import zipfile
import subprocess
from pathlib import Path
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
SAMPLE_DIR = DATA_DIR / "sample"

def generate_benchmark_sample(n_records: int = 10000, output_file: Path = None):
    """Generates a high-fidelity synthetic benchmark sample mirroring CSE-CIC-IDS2018.

    Enables instant out-of-the-box execution and testing of the entire 7-stage pipeline
    without requiring upfront download of 16 GB from Kaggle.
    """
    output_file = output_file or (SAMPLE_DIR / "cicids2018_sample.csv")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Generating {n_records} high-fidelity benchmark records matching CSE-CIC-IDS2018 schema...")

    np.random.seed(42)

    # Attack distributions: 60% Benign, 10% Recon, 8% BruteForce, 5% Infiltration, 5% Lateral, 5% Botnet, 7% DoS
    classes = [
        ("Benign", int(n_records * 0.60)),
        ("Reconnaissance", int(n_records * 0.10)),
        ("BruteForce", int(n_records * 0.08)),
        ("Infiltration", int(n_records * 0.05)),
        ("LateralMovement", int(n_records * 0.05)),
        ("Botnet_C2", int(n_records * 0.05)),
        ("DoS_DDoS", int(n_records * 0.07)),
    ]

    all_dfs = []
    base_time = pd.Timestamp("2018-02-14 08:00:00")

    internal_ips = ["192.168.10.50", "192.168.10.55", "192.168.10.56"]
    critical_ips = ["192.168.10.1", "192.168.10.5", "192.168.10.15", "192.168.10.20"]
    external_ips = ["203.0.113.19", "198.51.100.42", "185.220.101.5", "91.240.118.88"]

    current_time_offset = 0

    for label, count in classes:
        # Common flow features
        timestamps = [base_time + pd.Timedelta(seconds=current_time_offset + i * 0.2) for i in range(count)]
        current_time_offset += count * 0.2

        if label == "Benign":
            src_ips = np.random.choice(internal_ips, size=count)
            dst_ips = np.random.choice(critical_ips + external_ips, size=count)
            dst_ports = np.random.choice([80, 443, 53, 8080], size=count)
            durations = np.random.exponential(scale=500000, size=count).astype(int) + 1000
            fwd_pkts = np.random.poisson(lam=12, size=count) + 1
            bwd_pkts = np.random.poisson(lam=16, size=count) + 1
            fwd_bytes = fwd_pkts * np.random.randint(60, 500, size=count)
            bwd_bytes = bwd_pkts * np.random.randint(200, 1400, size=count)
            syn_flags = np.random.choice([0, 1], size=count, p=[0.9, 0.1])
            rst_flags = np.random.choice([0, 1], size=count, p=[0.98, 0.02])

        elif label == "Reconnaissance":
            src_ips = np.random.choice(external_ips, size=count)
            dst_ips = np.random.choice(critical_ips, size=count)
            # High port diversity (Port scan)
            dst_ports = np.random.randint(1, 1024, size=count)
            durations = np.random.randint(100, 5000, size=count)
            fwd_pkts = np.random.randint(1, 3, size=count)
            bwd_pkts = np.random.choice([0, 1], size=count, p=[0.8, 0.2])
            fwd_bytes = fwd_pkts * 40
            bwd_bytes = bwd_pkts * 40
            syn_flags = np.ones(count, dtype=int)
            rst_flags = np.random.choice([0, 1], size=count, p=[0.2, 0.8])

        elif label == "BruteForce":
            src_ips = np.random.choice(external_ips, size=count)
            dst_ips = np.random.choice(["192.168.10.20", "192.168.10.5"], size=count)
            dst_ports = np.random.choice([21, 22], size=count, p=[0.4, 0.6])
            durations = np.random.randint(20000, 80000, size=count)
            fwd_pkts = np.random.poisson(lam=8, size=count) + 2
            bwd_pkts = np.random.poisson(lam=6, size=count) + 1
            fwd_bytes = fwd_pkts * 90
            bwd_bytes = bwd_pkts * 60
            syn_flags = np.ones(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)

        elif label == "Infiltration":
            src_ips = np.random.choice(external_ips, size=count)
            dst_ips = np.random.choice(["192.168.10.20", "192.168.10.50"], size=count)
            dst_ports = np.random.choice([80, 443, 8080], size=count)
            durations = np.random.randint(50000, 300000, size=count)
            fwd_pkts = np.random.randint(20, 100, size=count)
            bwd_pkts = np.random.randint(5, 20, size=count)
            # Large forward payload containing exploit
            fwd_bytes = fwd_pkts * np.random.randint(800, 1500, size=count)
            bwd_bytes = bwd_pkts * 120
            syn_flags = np.ones(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)

        elif label == "LateralMovement":
            # Attacker pivoting from compromised internal workstation to DC or DB
            src_ips = np.full(count, "192.168.10.50")
            dst_ips = np.random.choice(["192.168.10.5", "192.168.10.15"], size=count)
            dst_ports = np.random.choice([445, 3389, 1433], size=count)
            durations = np.random.randint(10000, 150000, size=count)
            fwd_pkts = np.random.randint(10, 40, size=count)
            bwd_pkts = np.random.randint(10, 30, size=count)
            fwd_bytes = fwd_pkts * 200
            bwd_bytes = bwd_pkts * 250
            syn_flags = np.ones(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)

        elif label == "Botnet_C2":
            src_ips = np.random.choice(internal_ips, size=count)
            dst_ips = np.full(count, "198.51.100.42")
            dst_ports = np.random.choice([6667, 8080, 443], size=count)
            durations = np.random.randint(100000, 900000, size=count)
            fwd_pkts = np.random.randint(5, 15, size=count)
            bwd_pkts = np.random.randint(5, 15, size=count)
            fwd_bytes = fwd_pkts * 80
            bwd_bytes = bwd_pkts * 90
            syn_flags = np.random.choice([0, 1], size=count, p=[0.7, 0.3])
            rst_flags = np.zeros(count, dtype=int)

        elif label == "DoS_DDoS":
            src_ips = np.random.choice(external_ips, size=count)
            dst_ips = np.full(count, "192.168.10.20")
            dst_ports = np.full(count, 80)
            durations = np.random.randint(500, 10000, size=count)
            fwd_pkts = np.random.randint(50, 300, size=count)
            bwd_pkts = np.random.randint(0, 5, size=count)
            fwd_bytes = fwd_pkts * 64
            bwd_bytes = bwd_pkts * 40
            syn_flags = np.ones(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)

        sub_df = pd.DataFrame({
            "Timestamp": [t.strftime("%d/%m/%Y %H:%M:%S") for t in timestamps],
            "Src IP": src_ips,
            "Dst IP": dst_ips,
            "Dst Port": dst_ports,
            "Protocol": 6,
            "Flow Duration": durations,
            "Tot Fwd Pkts": fwd_pkts,
            "Tot Bwd Pkts": bwd_pkts,
            "TotLen Fwd Pkts": fwd_bytes,
            "TotLen Bwd Pkts": bwd_bytes,
            "Fwd Pkt Len Max": np.maximum(fwd_bytes // fwd_pkts + 20, 40),
            "Fwd Pkt Len Min": 40,
            "Fwd Pkt Len Mean": fwd_bytes / fwd_pkts,
            "Fwd Pkt Len Std": np.random.uniform(5.0, 50.0, size=count),
            "Bwd Pkt Len Max": np.maximum(bwd_bytes // np.maximum(bwd_pkts, 1) + 20, 40),
            "Bwd Pkt Len Min": 40,
            "Bwd Pkt Len Mean": bwd_bytes / np.maximum(bwd_pkts, 1),
            "Bwd Pkt Len Std": np.random.uniform(5.0, 50.0, size=count),
            "Flow Byts/s": (fwd_bytes + bwd_bytes) / np.maximum(durations * 1e-6, 1e-5),
            "Flow Pkts/s": (fwd_pkts + bwd_pkts) / np.maximum(durations * 1e-6, 1e-5),
            "Flow IAT Mean": durations / np.maximum(fwd_pkts + bwd_pkts, 1),
            "Flow IAT Std": np.random.uniform(10.0, 100.0, size=count),
            "Flow IAT Max": durations,
            "Flow IAT Min": np.random.randint(1, 10, size=count),
            "Fwd IAT Tot": durations,
            "Fwd IAT Mean": durations / fwd_pkts,
            "Fwd IAT Std": np.random.uniform(5.0, 50.0, size=count),
            "Fwd IAT Max": durations,
            "Fwd IAT Min": 1,
            "Bwd IAT Tot": durations,
            "Bwd IAT Mean": durations / np.maximum(bwd_pkts, 1),
            "Bwd IAT Std": np.random.uniform(5.0, 50.0, size=count),
            "Bwd IAT Max": durations,
            "Bwd IAT Min": 1,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "Fwd Header Len": fwd_pkts * 20,
            "Bwd Header Len": bwd_pkts * 20,
            "Fwd Pkts/s": fwd_pkts / np.maximum(durations * 1e-6, 1e-5),
            "Bwd Pkts/s": bwd_pkts / np.maximum(durations * 1e-6, 1e-5),
            "Pkt Len Min": 40,
            "Pkt Len Max": np.maximum(fwd_bytes // fwd_pkts, 40),
            "Pkt Len Mean": (fwd_bytes + bwd_bytes) / (fwd_pkts + bwd_pkts),
            "Pkt Len Std": np.random.uniform(10.0, 40.0, size=count),
            "Pkt Len Var": np.random.uniform(100.0, 1600.0, size=count),
            "FIN Flag Cnt": 0,
            "SYN Flag Cnt": syn_flags,
            "RST Flag Cnt": rst_flags,
            "PSH Flag Cnt": np.random.choice([0, 1], size=count, p=[0.7, 0.3]),
            "ACK Flag Cnt": np.random.choice([0, 1], size=count, p=[0.3, 0.7]),
            "URG Flag Cnt": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": bwd_pkts / fwd_pkts,
            "Pkt Size Avg": (fwd_bytes + bwd_bytes) / (fwd_pkts + bwd_pkts),
            "Init Fwd Win Byts": np.random.choice([8192, 29200, 65535], size=count),
            "Init Bwd Win Byts": np.random.choice([8192, 29200, 65535], size=count),
            "Fwd Act Data Pkts": fwd_pkts - 1,
            "Fwd Seg Size Min": 20,
            "Active Mean": durations * 0.8,
            "Active Std": 0,
            "Active Max": durations * 0.8,
            "Active Min": durations * 0.8,
            "Idle Mean": 0,
            "Idle Std": 0,
            "Idle Max": 0,
            "Idle Min": 0,
            "Label": label,
        })
        all_dfs.append(sub_df)

    final_df = pd.concat(all_dfs, ignore_index=True)
    final_df.to_csv(output_file, index=False)
    print(f"[+] Successfully generated benchmark dataset at: {output_file} ({len(final_df)} rows)")
    return final_df

def download_from_kaggle():
    """Instructions and automated trigger for downloading full 16GB dataset from Kaggle."""
    dataset_name = "solarmainframe/ids-intrusion-csv"
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    print("======================================================================")
    print("  Kaggle Dataset: solarmainframe/ids-intrusion-csv")
    print("======================================================================")
    print(f"To download the full 16GB CSE-CIC-IDS2018 dataset directly:")
    print(f"  1. Ensure you have your Kaggle API key at ~/.kaggle/kaggle.json")
    print(f"  2. Run command:")
    print(f"     kaggle datasets download -d {dataset_name} -p {RAW_DIR} --unzip")
    print("======================================================================")

    if shutil.which("kaggle"):
        print("[*] Kaggle CLI detected. Attempting automated download...")
        try:
            cmd = ["kaggle", "datasets", "download", "-d", dataset_name, "-p", str(RAW_DIR), "--unzip"]
            subprocess.run(cmd, check=True)
            print("[+] Full dataset downloaded successfully!")
        except subprocess.CalledProcessError as e:
            print(f"[-] Kaggle download command exited with error: {e}")
            print("[*] Generating benchmark dataset fallback...")
            generate_benchmark_sample()
    else:
        print("[!] Kaggle CLI not found in PATH. Generating built-in benchmark dataset...")
        generate_benchmark_sample()

if __name__ == "__main__":
    if "--download-full" in sys.argv:
        download_from_kaggle()
    else:
        generate_benchmark_sample()
