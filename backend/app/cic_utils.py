"""
CICIDS2017 prediction path for SentryNet.

Random Forest      = primary attack detector (threshold in RF_THRESHOLD).
Isolation Forest   = supplementary "unusual traffic" flag only. It never turns a
                     normal prediction into a confirmed attack (the OR-combination
                     was measured and rejected, see backend/cic_hybrid_comparison.json).
Only CICIDS files are loaded here. The NSL-KDD files are never touched.
"""
import math
import os
from pathlib import Path

import joblib
import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parents[1]

# ---- configuration -------------------------------------------------------
# Chosen on Thursday validation data (backend/cic_metrics.json). Override with an
# environment variable, e.g.  $env:SENTRYNET_RF_THRESHOLD = "0.3"
RF_THRESHOLD = float(os.getenv("SENTRYNET_RF_THRESHOLD", "0.2"))
if not 0.0 < RF_THRESHOLD < 1.0:
    raise RuntimeError("SENTRYNET_RF_THRESHOLD must be between 0 and 1")

# Calibrated to ~1% false alarms on Thursday BENIGN traffic
# (backend/if_experiment_results.json). Lower score = more unusual.
IF_SCORE_THRESHOLD = -0.6243491503864139

# ---- load models ---------------------------------------------------------
feature_columns = list(joblib.load(BACKEND_DIR / "cic_columns.pkl"))
rf_model = joblib.load(BACKEND_DIR / "cic_binary_model.pkl")
if_model = joblib.load(BACKEND_DIR / "cic_isolation_model.pkl")

if len(feature_columns) != 78:
    raise RuntimeError(f"Expected 78 CICIDS features, found {len(feature_columns)}")
if list(rf_model.feature_names_in_) != feature_columns:
    raise RuntimeError("Random Forest feature names/order differ from cic_columns.pkl")
if list(if_model.feature_names_in_) != feature_columns:
    raise RuntimeError("Isolation Forest feature names/order differ from cic_columns.pkl")

ATTACK_INDEX = list(rf_model.classes_).index(1)   # classes are 0 (BENIGN) and 1 (attack)


def model_info() -> dict:
    return {
        "dataset": "CICIDS2017",
        "feature_count": len(feature_columns),
        "rf_threshold": RF_THRESHOLD,
        "if_score_threshold": IF_SCORE_THRESHOLD,
        "isolation_forest_role": "supplementary unusual-traffic flag only; never a confirmed attack",
        "attack_family_model": "not available (attack category is 'unknown')",
    }


def build_frame(records: list) -> pd.DataFrame:
    """Validate records and build a DataFrame with the exact 78 columns in training order."""
    rows = []
    for rec in records:
        missing = [c for c in feature_columns if c not in rec]
        if missing:
            raise ValueError(
                f"missing {len(missing)} of {len(feature_columns)} required features, e.g. {missing[:5]}"
            )
        row = []
        for c in feature_columns:
            try:
                value = float(rec[c])
            except (TypeError, ValueError):
                raise ValueError(f"feature '{c}' is not a number: {rec[c]!r}")
            if not math.isfinite(value):
                raise ValueError(f"feature '{c}' is NaN or infinite")
            row.append(value)
        rows.append(row)
    return pd.DataFrame(rows, columns=feature_columns)


def predict_flows(records: list) -> list:
    if not records:
        return []
    X = build_frame(records)
    probabilities = rf_model.predict_proba(X)[:, ATTACK_INDEX]
    anomaly_scores = if_model.score_samples(X)

    results = []
    for p, s in zip(probabilities, anomaly_scores):
        p = float(p)
        s = float(s)
        is_attack = p >= RF_THRESHOLD
        is_unusual = s < IF_SCORE_THRESHOLD

        if is_attack:
            label, category, source = "attack", "unknown", "random_forest"
        elif is_unusual:
            label, category, source = "normal", "normal", "isolation_forest_flag"
        else:
            label, category, source = "normal", "normal", "none"

        results.append({
            "label": label,
            "category": category,
            "attack_probability": round(p, 4),
            "risk_score": round(p * 100, 1),      # heuristic prioritisation, not calibrated
            "anomaly_score": round(s, 4),
            "anomaly_detected": bool(is_unusual),
            "detection_source": source,
        })
    return results


def predict_flow(record: dict) -> dict:
    return predict_flows([record])[0]