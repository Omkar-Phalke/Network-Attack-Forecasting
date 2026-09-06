"""Stage 7: SOC Dashboard & Real-Time Visualization Web Server.

Flask backend serving real-time telemetry streaming, interactive network attack graph,
next-stage forecasting timeline, SHAP explainability, and what-if simulation sandbox.
"""

from typing import Dict, Any, List
import json
from pathlib import Path
from flask import Flask, render_template, jsonify, request, Response
import pandas as pd
import numpy as np

# Project imports
from src.config import BASE_DIR, SAMPLE_DATA_DIR, MODELS_DIR, KILL_CHAIN_STAGES, CRITICAL_ASSETS
from src.stage1_ingestion.csv_loader import CICIDS2018Loader
from src.stage1_ingestion.stream_simulator import NetworkStreamSimulator
from src.stage2_preprocessing.cleaner import TrafficDataCleaner
from src.stage2_preprocessing.normalizer import TrafficNormalizer
from src.stage2_preprocessing.enricher import TrafficEnricher
from src.stage3_feature_engineering.flow_features import FlowFeatureExtractor
from src.stage3_feature_engineering.temporal_features import TemporalFeatureExtractor
from src.stage3_feature_engineering.behavioral_features import BehavioralFeatureExtractor
from src.stage3_feature_engineering.graph_builder import HostGraphBuilder
from src.stage4_intelligence.anomaly_detector import AnomalyDetector
from src.stage4_intelligence.attack_classifier import AttackClassifier
from src.stage4_intelligence.kill_chain_estimator import KillChainEstimator
from src.stage4_intelligence.attack_forecaster import AttackForecaster
from src.stage5_risk_assessment.risk_engine import RiskScoringEngine
from src.stage5_risk_assessment.infiltration_exfil import InfiltrationExfilAnalyzer
from src.stage5_risk_assessment.attack_graph_projector import AttackGraphProjector
from src.stage6_explainability.explainer import ThreatExplainer
from src.stage6_explainability.what_if_simulator import WhatIfSimulator
from src.stage6_explainability.response_engine import AutomatedResponseEngine
from src.stage6_explainability.mitigation_generator import MitigationRuleGenerator

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")

# Global In-Memory State for the SOC Command Center
class SOCState:
    def __init__(self):
        self.stream_simulator = None
        self.cleaner = TrafficDataCleaner()
        self.normalizer = TrafficNormalizer(feature_cols=["Flow Duration", "Flow Byts/s", "Flow Pkts/s"])
        self.enricher = TrafficEnricher()
        self.graph_builder = HostGraphBuilder()
        self.anomaly_detector = AnomalyDetector()
        self.classifier = AttackClassifier()
        self.estimator = KillChainEstimator()
        self.forecaster = AttackForecaster()
        self.risk_engine = RiskScoringEngine()
        self.explainer = ThreatExplainer()

        self.latest_alerts = []
        self.latest_forecast = {}
        self.latest_risk = {"risk_score": 12.0, "risk_level": "Low"}
        self.total_processed_flows = 0
        self.threat_actors = set()
        self.compromised_hosts = set()

    def initialize(self):
        # Load sample dataset
        sample_path = SAMPLE_DATA_DIR / "cicids2018_sample.csv"
        if not sample_path.exists():
            from data.download_kaggle import generate_benchmark_sample
            generate_benchmark_sample(output_file=sample_path)

        raw_df = pd.read_csv(sample_path)
        # Preprocess baseline
        clean_df = self.cleaner.clean(raw_df, is_training=True)
        norm_df = self.normalizer.standardize_timestamps(clean_df)
        norm_df = self.normalizer.fit_transform(norm_df)
        enriched_df = self.enricher.enrich(norm_df)

        df_flow = FlowFeatureExtractor.extract(enriched_df)
        df_temp = TemporalFeatureExtractor.extract(df_flow)
        df_behav = BehavioralFeatureExtractor.extract(df_temp)
        self.graph_builder.build_from_dataframe(df_behav)
        featured_df = self.graph_builder.compute_graph_metrics(df_behav)

        # Fit or load models
        model_path = MODELS_DIR / "attack_classifier.joblib"
        anomaly_path = MODELS_DIR / "anomaly_detector.joblib"

        if model_path.exists() and anomaly_path.exists():
            self.classifier.load(model_path)
            self.anomaly_detector.load(anomaly_path)
        else:
            self.anomaly_detector.fit(featured_df)
            self.classifier.fit(featured_df, target_col="Label")
            self.anomaly_detector.save(anomaly_path)
            self.classifier.save(model_path)

        # Initialize real-time telemetry stream simulator
        self.stream_simulator = NetworkStreamSimulator(featured_df, playback_speed=1.0)
        print("[+] SOC Command Center initialized with models and streaming telemetry.")

soc_state = SOCState()

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/forecast")
def forecast_view():
    return render_template("forecast_view.html")

@app.route("/reports")
def reports_view():
    return render_template("reports.html")

@app.route("/api/stream/next", methods=["GET"])
def get_next_stream_batch():
    """Fetches next batch of streaming network flows, evaluates them, and updates SOC state."""
    batch_size = int(request.args.get("batch_size", 5))
    batch_df = soc_state.stream_simulator.get_next_batch(batch_size=batch_size)

    # Predict anomalies and attack classes
    _, anomaly_scores = soc_state.anomaly_detector.predict(batch_df)
    preds, probs = soc_state.classifier.predict(batch_df)

    batch_results = []
    for i, (_, row) in enumerate(batch_df.iterrows()):
        soc_state.total_processed_flows += 1
        rec = row.to_dict()
        pred_label = preds[i]
        confidence = float(np.max(probs[i]))
        anom_score = float(anomaly_scores[i])

        # Kill Chain state estimation
        current_stage = soc_state.estimator.estimate_stage(pred_label, rec)
        rec_eval = soc_state.estimator.record_and_evaluate(rec["Src IP"], current_stage)

        # Risk scoring
        dst_crit = float(rec.get("dst_asset_criticality", 0.4))
        risk_profile = soc_state.risk_engine.calculate_score(
            attack_prob=confidence if pred_label != "Benign" else 0.05,
            kill_chain_stage=current_stage,
            asset_criticality=dst_crit,
            anomaly_score=anom_score,
        )

        # Forecasting
        forecast = soc_state.forecaster.forecast_next_stage(
            current_stage,
            flow_rate=float(rec.get("rolling_conn_rate_60s", 1.0))
        )
        soc_state.latest_forecast = forecast
        soc_state.latest_risk = risk_profile

        # Infiltration & Exfiltration checks
        infil_res = InfiltrationExfilAnalyzer.assess_infiltration(rec)
        exfil_res = InfiltrationExfilAnalyzer.assess_exfiltration(rec)

        # Threat actor and compromised asset tracking
        if pred_label != "Benign":
            soc_state.threat_actors.add(rec["Src IP"])
            if current_stage >= 3:
                soc_state.compromised_hosts.add(rec["Dst IP"])

            # Automated SOAR action
            soar_action = AutomatedResponseEngine.execute_policy(
                src_ip=rec["Src IP"],
                dst_ip=rec["Dst IP"],
                risk_score=risk_profile["risk_score"],
                risk_level=risk_profile["risk_level"],
                predicted_stage=forecast["predicted_next_stage"],
                predicted_stage_name=forecast["next_stage_name"],
            )

            # Record alert
            alert_entry = {
                "id": soc_state.total_processed_flows,
                "timestamp": rec.get("timestamp_iso", "2018-02-14 08:00:00"),
                "src_ip": rec["Src IP"],
                "dst_ip": rec["Dst IP"],
                "dst_port": rec["Dst Port"],
                "service": rec.get("service_name", "HTTP"),
                "attack_class": pred_label,
                "confidence": round(confidence * 100, 1),
                "risk_score": risk_profile["risk_score"],
                "risk_level": risk_profile["risk_level"],
                "kill_chain_stage": current_stage,
                "predicted_next_stage": forecast["predicted_next_stage"],
                "next_stage_name": forecast["next_stage_name"],
                "tti_minutes": forecast["estimated_time_to_impact_minutes"],
                "soar_policy": soar_action["policy_action_type"],
            }
            soc_state.latest_alerts.insert(0, alert_entry)
            if len(soc_state.latest_alerts) > 100:
                soc_state.latest_alerts.pop()

        flow_item = {
            "flow_id": soc_state.total_processed_flows,
            "timestamp": rec.get("timestamp_iso", "2018-02-14 08:00:00"),
            "src_ip": rec["Src IP"],
            "dst_ip": rec["Dst IP"],
            "dst_port": rec["Dst Port"],
            "bytes": int(rec.get("TotLen Fwd Pkts", 0)),
            "label": pred_label,
            "confidence": round(confidence * 100, 1),
            "risk_score": risk_profile["risk_score"],
            "risk_level": risk_profile["risk_level"],
            "stage_name": rec_eval["stage_name"],
            "predicted_next_stage": forecast["next_stage_name"],
            "tti_minutes": forecast["estimated_time_to_impact_minutes"],
        }
        batch_results.append(flow_item)

    return jsonify({
        "status": "success",
        "processed_batch": batch_results,
        "latest_risk": soc_state.latest_risk,
        "latest_forecast": soc_state.latest_forecast,
        "metrics": {
            "total_flows": soc_state.total_processed_flows,
            "active_threat_actors": len(soc_state.threat_actors),
            "compromised_hosts": len(soc_state.compromised_hosts),
            "total_alerts": len(soc_state.latest_alerts),
        }
    })

@app.route("/api/graph/current", methods=["GET"])
def get_current_graph():
    """Returns the live network topology graph with node risk statuses."""
    vis_data = soc_state.graph_builder.to_visualization_json()
    # Update node colors if compromised or attacker
    for node in vis_data["nodes"]:
        if node["id"] in soc_state.threat_actors:
            node["color"] = {"background": "#ef4444", "border": "#ffffff"}
            node["title"] += "<br><b>ALERT: Active Attacker IP</b>"
        elif node["id"] in soc_state.compromised_hosts:
            node["color"] = {"background": "#f97316", "border": "#ffffff"}
            node["title"] += "<br><b>ALERT: Infiltrated / Compromised Host</b>"
    return jsonify(vis_data)

@app.route("/api/graph/forecast", methods=["GET"])
def get_forecast_graph():
    """Returns future attack graph projecting anticipated pivot hops."""
    projector = AttackGraphProjector(soc_state.graph_builder.graph)
    target_stage = soc_state.latest_forecast.get("predicted_next_stage", 3)
    threat_ips = list(soc_state.threat_actors) or ["203.0.113.19"]
    projected = projector.project_future_attack_graph(
        compromised_ips=threat_ips[:2],
        forecasted_stage=target_stage,
    )
    return jsonify(projected)

@app.route("/api/whatif", methods=["POST"])
def run_what_if_simulation():
    """Runs counterfactual simulation of security mitigations."""
    data = request.json or {}
    pre_score = float(data.get("risk_score", soc_state.latest_risk.get("risk_score", 75.0)))
    pre_stage = int(data.get("kill_chain_stage", 3))

    res = WhatIfSimulator.simulate_intervention(
        pre_risk_score=pre_score,
        pre_kill_chain_stage=pre_stage,
        block_source_ip=bool(data.get("block_source_ip", False)),
        quarantine_host=bool(data.get("quarantine_host", False)),
        rate_limit_ports=data.get("rate_limit_ports", []),
        restrict_cross_subnet=bool(data.get("restrict_cross_subnet", False)),
    )
    return jsonify(res)

@app.route("/api/explain", methods=["GET"])
def get_explanation():
    """Returns SHAP feature attribution waterfall explaining forecast."""
    sample_flow = {
        "rolling_conn_rate_60s": 35.0,
        "dst_port_entropy": 2.8,
        "rolling_syn_ratio_60s": 0.85,
        "payload_asymmetry_ratio": 1.4,
        "cross_subnet_flag": 1,
        "Dst Port": 22,
        "Flow Duration": 45000,
    }
    explanation = soc_state.explainer.explain_flow(sample_flow)
    return jsonify(explanation)

@app.route("/api/mitigation", methods=["GET"])
def get_mitigation():
    """Returns generated firewall rules, Suricata signatures, and checklist."""
    src = request.args.get("src_ip", "203.0.113.19")
    dst = request.args.get("dst_ip", "192.168.10.20")
    port = int(request.args.get("port", 80))
    attack = request.args.get("attack", "BruteForce")
    stage_name = request.args.get("stage_name", "Initial Access & Brute Force")

    package = MitigationRuleGenerator.generate_full_mitigation_package(
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        attack_type=attack,
        forecasted_stage_name=stage_name,
    )
    return jsonify(package)

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Returns forensic alert records."""
    return jsonify(soc_state.latest_alerts)

@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    """Exports alerts table as downloadable CSV."""
    if not soc_state.latest_alerts:
        df_alerts = pd.DataFrame(columns=[
            "id", "timestamp", "src_ip", "dst_ip", "dst_port", "service",
            "attack_class", "confidence", "risk_score", "risk_level",
            "kill_chain_stage", "predicted_next_stage", "next_stage_name",
            "tti_minutes", "soar_policy"
        ])
    else:
        df_alerts = pd.DataFrame(soc_state.latest_alerts)
    csv_str = df_alerts.to_csv(index=False)
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=SIH26153_forensic_alerts.csv"}
    )

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5050))
    soc_state.initialize()
    print("======================================================================")
    print(f"  SOC Command Center running at: http://127.0.0.1:{port}")
    print("======================================================================")
    app.run(host="0.0.0.0", port=port, debug=False)
