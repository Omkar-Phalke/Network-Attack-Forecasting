"""End-to-End CLI Demonstration of NetAttackForecast-AI (Stages 1 through 6).

Executes the full pipeline for SIH26153:
1. Ingestion (CSE-CIC-IDS2018 dataset)
2. Preprocessing & Normalization
3. Feature Engineering & Dynamic Host Graph
4. AI/ML Intelligence Layer (Anomaly Detection, Classification, Kill Chain, Forecasting)
5. Risk Assessment & Forecasting
6. Explainability & Automated Response
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np

# Project imports
from src.config import BASE_DIR, SAMPLE_DATA_DIR, ALL_MODEL_FEATURES, MODELS_DIR
from src.stage1_ingestion.csv_loader import CICIDS2018Loader
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
from src.stage4_intelligence.drift_detector import DriftDetector
from src.stage5_risk_assessment.risk_engine import RiskScoringEngine
from src.stage5_risk_assessment.infiltration_exfil import InfiltrationExfilAnalyzer
from src.stage5_risk_assessment.attack_graph_projector import AttackGraphProjector
from src.stage6_explainability.explainer import ThreatExplainer
from src.stage6_explainability.what_if_simulator import WhatIfSimulator
from src.stage6_explainability.response_engine import AutomatedResponseEngine
from src.stage6_explainability.mitigation_generator import MitigationRuleGenerator
from src.utils.metrics import compute_classification_metrics, compute_forecasting_lead_time_metrics

def main():
    print("=" * 80)
    print("  SIH26153: AI-BASED NETWORK ATTACK FORECASTING FROM NETWORK TRAFFIC")
    print("  End-to-End Pipeline Execution (Stages 1 - 6)")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # Stage 1: Data Sources & Ingestion
    # --------------------------------------------------------------------------
    print("\n[+] STAGE 1: Data Sources & Security Ingestion")
    sample_csv = SAMPLE_DATA_DIR / "cicids2018_sample.csv"
    if not sample_csv.exists():
        print("[-] Sample dataset not found. Generating now...")
        from data.download_kaggle import generate_benchmark_sample
        generate_benchmark_sample(n_records=10000, output_file=sample_csv)

    loader = CICIDS2018Loader(sample_csv)
    raw_df = loader.load_sample(n_rows=10000)
    print(f"    Loaded {len(raw_df)} network flow records. Available classes: {dict(raw_df['Label'].value_counts())}")

    # --------------------------------------------------------------------------
    # Stage 2: Preprocessing & Normalization
    # --------------------------------------------------------------------------
    print("\n[+] STAGE 2: Preprocessing & Normalization")
    cleaner = TrafficDataCleaner()
    cleaned_df = cleaner.clean(raw_df, is_training=True)

    normalizer = TrafficNormalizer(feature_cols=["Flow Duration", "Flow Byts/s", "Flow Pkts/s"])
    normalized_df = normalizer.standardize_timestamps(cleaned_df)
    normalized_df = normalizer.fit_transform(normalized_df)

    enricher = TrafficEnricher()
    enriched_df = enricher.enrich(normalized_df)
    qa_report = enricher.validate_quality(enriched_df)
    print(f"    Data QA Status: {qa_report['quality_status']} | Missing cells: {qa_report['total_null_cells']}")

    # --------------------------------------------------------------------------
    # Stage 3: Feature Engineering & Dynamic Host Graph
    # --------------------------------------------------------------------------
    print("\n[+] STAGE 3: Feature Engineering & Dynamic Host Communication Graph")
    df_flow = FlowFeatureExtractor.extract(enriched_df)
    df_temp = TemporalFeatureExtractor.extract(df_flow)
    df_behav = BehavioralFeatureExtractor.extract(df_temp)

    graph_builder = HostGraphBuilder()
    graph = graph_builder.build_from_dataframe(df_behav)
    featured_df = graph_builder.compute_graph_metrics(df_behav)
    print(f"    Dynamic Host Graph G(V, E) built: {len(graph.nodes)} host nodes, {len(graph.edges)} communication edges.")
    print(f"    Extracted features count: {len(featured_df.columns)} columns.")

    # --------------------------------------------------------------------------
    # Stage 4: AI/ML Intelligence Layer
    # --------------------------------------------------------------------------
    print("\n[+] STAGE 4: AI/ML Intelligence Layer")

    # Split train/test (80/20)
    train_size = int(len(featured_df) * 0.8)
    train_df = featured_df.iloc[:train_size].copy()
    test_df = featured_df.iloc[train_size:].copy()

    # 1. Unsupervised Anomaly Detection (Isolation Forest)
    print("    [4.1] Training Anomaly Detector (Isolation Forest)...")
    anomaly_det = AnomalyDetector(contamination=0.08)
    anomaly_det.fit(train_df)
    is_anomaly, anomaly_scores = anomaly_det.predict(test_df)
    test_df["is_anomaly"] = is_anomaly
    test_df["anomaly_score"] = anomaly_scores
    print(f"          Detected {sum(is_anomaly)} anomalous flows out of {len(test_df)} test flows.")

    # 2. Supervised Attack Classification (Multi-class Random Forest)
    print("    [4.2] Training Multi-Class Attack Classifier...")
    classifier = AttackClassifier(n_estimators=60)
    classifier.fit(train_df, target_col="Label")
    preds, probs = classifier.predict(test_df)
    test_df["predicted_class"] = preds
    test_df["attack_confidence"] = np.max(probs, axis=1)

    eval_metrics = compute_classification_metrics(test_df["Label"].tolist(), preds.tolist())
    print(f"          Classification Accuracy: {eval_metrics['accuracy'] * 100:.2f}% | Weighted F1: {eval_metrics['weighted_f1']:.4f}")

    # Top feature importances
    top_importances = classifier.get_feature_importances(top_n=5)
    print(f"          Top Predictive Features: {[f['feature'] for f in top_importances]}")

    # 3. Kill Chain State Estimation & Attack Forecasting
    print("    [4.3] Estimating Kill Chain States & Forecasting Next Stages...")
    estimator = KillChainEstimator()
    forecaster = AttackForecaster()

    sample_threat_row = test_df[test_df["Label"] != "Benign"].iloc[0].to_dict()
    current_stage = estimator.estimate_stage(sample_threat_row["Label"], sample_threat_row)
    forecast_result = forecaster.forecast_next_stage(current_stage, flow_rate=float(sample_threat_row.get("rolling_conn_rate_60s", 10.0)))
    trajectory = forecaster.forecast_trajectory(current_stage, steps=3)

    print(f"          Target Sample Attack: {sample_threat_row['Label']} from {sample_threat_row['Src IP']} -> {sample_threat_row['Dst IP']}")
    print(f"          Current Estimated Stage: {current_stage} ({forecast_result['current_stage']})")
    print(f"          >> FORECASTED NEXT STAGE: {forecast_result['predicted_next_stage']} ({forecast_result['next_stage_name']})")
    print(f"          >> TRANSITION PROBABILITY: {forecast_result['transition_probability'] * 100:.1f}%")
    print(f"          >> ESTIMATED TIME-TO-IMPACT: {forecast_result['estimated_time_to_impact_minutes']} minutes")

    # 4. Continuous Drift Detection Loop
    print("    [4.4] Continuous Learning Drift Monitor (PSI & KS Test)...")
    drift_detector = DriftDetector(train_df, monitored_features=["rolling_conn_rate_60s", "dst_port_entropy", "Flow Byts/s"])
    drift_result = drift_detector.evaluate_drift(test_df)
    print(f"          Drift Evaluation Status: {drift_result['overall_drift_status']} (Retrain required: {drift_result['retrain_recommended']})")

    # --------------------------------------------------------------------------
    # Stage 5: Risk Assessment & Forecasting
    # --------------------------------------------------------------------------
    print("\n[+] STAGE 5: Risk Assessment & Future Attack Graph")
    risk_engine = RiskScoringEngine()
    risk_profile = risk_engine.calculate_score(
        attack_prob=float(sample_threat_row.get("attack_confidence", 0.9)),
        kill_chain_stage=current_stage,
        asset_criticality=float(sample_threat_row.get("dst_asset_criticality", 0.85)),
        anomaly_score=float(sample_threat_row.get("anomaly_score", 0.7)),
    )
    print(f"    Dynamic Risk Score: {risk_profile['risk_score']}/100 [Level: {risk_profile['risk_level']}]")
    print(f"    Risk Breakdown: {risk_profile['components']}")

    # Infiltration / Exfiltration Analytics
    infil_res = InfiltrationExfilAnalyzer.assess_infiltration(sample_threat_row)
    exfil_res = InfiltrationExfilAnalyzer.assess_exfiltration(sample_threat_row)
    print(f"    Infiltration Risk: {infil_res['infiltration_risk']}% | Alert: {infil_res['is_infiltration_alert']}")
    print(f"    Exfiltration Risk: {exfil_res['exfiltration_risk']}% | Alert: {exfil_res['is_exfiltration_alert']}")

    # Future Attack Graph Projection
    graph_projector = AttackGraphProjector(graph)
    future_graph = graph_projector.project_future_attack_graph(
        compromised_ips=[sample_threat_row["Src IP"]],
        forecasted_stage=forecast_result["predicted_next_stage"],
    )
    print(f"    Projected Future Attack Graph: {len(future_graph['projected_nodes'])} nodes at risk, {len(future_graph['projected_edges'])} predicted pivot vectors.")

    # --------------------------------------------------------------------------
    # Stage 6: Explainability & Automated Response
    # --------------------------------------------------------------------------
    print("\n[+] STAGE 6: Explainability & Automated Response")
    explainer = ThreatExplainer()
    explanation = explainer.explain_flow(sample_threat_row)
    print(f"    SHAP Attribution: {explanation['summary']}")
    for f in explanation["top_features"]:
        print(f"      * {f['feature']}: {f['impact_percentage']}% impact ({f['explanation']})")

    # What-If Counterfactual Sandbox
    what_if = WhatIfSimulator.simulate_intervention(
        pre_risk_score=risk_profile["risk_score"],
        pre_kill_chain_stage=current_stage,
        block_source_ip=True,
        quarantine_host=True,
    )
    print(f"\n    [What-If Simulation] Simulating Automated Containment (Block IP & Quarantine Host):")
    print(f"      Baseline Risk: {what_if['baseline_risk_score']} -> Post-Intervention Risk: {what_if['simulated_risk_score']}")
    print(f"      Delta Risk: {what_if['delta_risk']} ({what_if['risk_reduction_percentage']}% reduction)")
    print(f"      Containment Status: {what_if['containment_status']} [Projected Stage: {what_if['projected_stage_name']}]")

    # Automated Response Engine (SOAR)
    response_result = AutomatedResponseEngine.execute_policy(
        src_ip=sample_threat_row["Src IP"],
        dst_ip=sample_threat_row["Dst IP"],
        risk_score=risk_profile["risk_score"],
        risk_level=risk_profile["risk_level"],
        predicted_stage=forecast_result["predicted_next_stage"],
        predicted_stage_name=forecast_result["next_stage_name"],
    )
    print(f"\n    [Automated SOAR Action] Policy Triggered: {response_result['policy_action_type']}")
    for act in response_result["actions_executed"]:
        print(f"      -> Action: {act['action']} on {act.get('target', act.get('channel'))} ({act['status']})")

    # Mitigation Package
    mitigation = MitigationRuleGenerator.generate_full_mitigation_package(
        src_ip=sample_threat_row["Src IP"],
        dst_ip=sample_threat_row["Dst IP"],
        dst_port=int(sample_threat_row.get("Dst Port", 80)),
        attack_type=sample_threat_row["Label"],
        forecasted_stage_name=forecast_result["next_stage_name"],
    )
    print(f"\n    [Generated Mitigation Rule]:")
    print(f"      {mitigation['firewall_rules']['iptables'][1]}")
    print(f"      {mitigation['ids_signatures']['suricata']}")

    # Save models for SOC Dashboard usage
    print("\n[+] Persisting Trained Models to models/ directory...")
    anomaly_det.save()
    classifier.save()

    print("\n" + "=" * 80)
    print("  [SUCCESS] All 6 Stages of the pipeline executed with complete fidelity!")
    print("  Launch the interactive SOC Dashboard next using: python app.py")
    print("=" * 80)

if __name__ == "__main__":
    main()
