#!/usr/bin/env bash
# ==============================================================================
# Setup script for SIH26153: AI-Based Network Attack Forecasting
# ==============================================================================
set -e

echo "======================================================================"
echo "  SIH26153 — AI-Based Network Attack Forecasting from Traffic Data"
echo "  Setting up Python Virtual Environment and Dependencies..."
echo "======================================================================"

if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is not installed or not in PATH."
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment 'venv'..."
    python3 -m venv venv
else
    echo "[*] Existing virtual environment found."
fi

echo "[+] Activating virtual environment..."
source venv/bin/activate

echo "[+] Upgrading pip..."
pip install --upgrade pip

echo "[+] Installing project requirements..."
pip install -r requirements.txt

echo "======================================================================"
echo "  Setup Completed Successfully!"
echo "  - To run CLI Demo:             python run_demo.py"
echo "  - To start SOC Web Dashboard:  python app.py"
echo "  - To run Test Suite:           python -m unittest discover tests"
echo "======================================================================"
