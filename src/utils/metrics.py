"""Evaluation and forensic metric utilities for SIH26153."""

from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

def compute_classification_metrics(y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
    """Computes overall accuracy, weighted F1, and per-class metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    labels = sorted(list(set(y_true) | set(y_pred)))
    cm = confusion_matrix(y_true, y_pred, labels=labels).tolist()

    return {
        "accuracy": round(acc, 4),
        "weighted_f1": round(f1, 4),
        "labels": labels,
        "confusion_matrix": cm,
        "per_class": {
            cls: {
                "precision": round(report[cls]["precision"], 4),
                "recall": round(report[cls]["recall"], 4),
                "f1_score": round(report[cls]["f1-score"], 4),
                "support": int(report[cls]["support"]),
            }
            for cls in labels if cls in report
        }
    }

def compute_forecasting_lead_time_metrics(
    actual_stages: List[int],
    predicted_stages: List[int],
    lead_times_minutes: List[float]
) -> Dict[str, Any]:
    """Evaluates forecasting accuracy and average lead time before attack execution."""
    stage_match = np.array(actual_stages) == np.array(predicted_stages)
    stage_accuracy = float(np.mean(stage_match)) if len(actual_stages) > 0 else 0.0
    avg_lead_time = float(np.mean(lead_times_minutes)) if len(lead_times_minutes) > 0 else 0.0

    return {
        "stage_forecasting_accuracy": round(stage_accuracy, 4),
        "avg_lead_time_minutes": round(avg_lead_time, 2),
        "total_forecasting_windows": len(actual_stages),
    }
