import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    confusion_matrix, precision_score,
    recall_score, f1_score
)

DATA = "data/cicids_ready"
BACKEND = "backend"
CHUNK = 50000

print("=" * 65)
print("SENTRYNET - FINAL HYBRID COMPARISON")
print("=" * 65)

rf = joblib.load(os.path.join(BACKEND, "cic_binary_model.pkl"))
iso = joblib.load(os.path.join(BACKEND, "cic_isolation_model.pkl"))
columns = joblib.load(os.path.join(BACKEND, "cic_columns.pkl"))

RF_THRESHOLD = 0.2
IF_TARGET_FPR = 0.01

def load_data(path):
    frames = []
    for chunk in pd.read_csv(path, chunksize=CHUNK):
        frames.append(chunk)
    return pd.concat(frames, ignore_index=True)

print("\nLoading validation and Friday datasets...")
val = load_data(os.path.join(DATA, "validation.csv"))
test = load_data(os.path.join(DATA, "test.csv"))

def features(df):
    X = df[columns].astype(np.float32)
    if not np.isfinite(X.to_numpy()).all():
        raise ValueError("Invalid feature values found.")
    return X

print("Calculating Thursday anomaly threshold...")
X_val = features(val)
val_benign = val["is_attack"].to_numpy() == 0

val_scores = iso.score_samples(X_val)
if_threshold = float(
    np.quantile(val_scores[val_benign], IF_TARGET_FPR)
)

print("Isolation Forest threshold:", if_threshold)

def predictions(df):
    X = features(df)

    attack_index = list(rf.classes_).index(1)
    rf_prob = rf.predict_proba(X)[:, attack_index]
    rf_pred = (rf_prob >= RF_THRESHOLD).astype(int)

    iso_scores = iso.score_samples(X)
    iso_pred = (iso_scores <= if_threshold).astype(int)

    hybrid = np.logical_or(rf_pred, iso_pred).astype(int)

    return rf_pred, iso_pred, hybrid

print("\nEvaluating validation...")
val_rf, val_iso, val_hybrid = predictions(val)

print("Evaluating Friday test...")
test_rf, test_iso, test_hybrid = predictions(test)

def metrics(y, pred):
    tn, fp, fn, tp = confusion_matrix(
        y, pred, labels=[0, 1]
    ).ravel()

    return {
        "precision": float(precision_score(
            y, pred, zero_division=0
        )),
        "recall": float(recall_score(
            y, pred, zero_division=0
        )),
        "f1": float(f1_score(
            y, pred, zero_division=0
        )),
        "false_positive_rate": float(
            fp / (fp + tn) if (fp + tn) else 0
        ),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp)
    }

def compare(name, y, rf_pred, iso_pred, hybrid_pred):
    print("\n", name)

    results = {
        "random_forest": metrics(y, rf_pred),
        "isolation_forest": metrics(y, iso_pred),
        "hybrid": metrics(y, hybrid_pred)
    }

    for model_name, result in results.items():
        print("\n", model_name.upper())
        for key, value in result.items():
            print(f"{key}: {value}")

    # How many attacks IF recovers that RF missed?
    missed_by_rf = (y == 1) & (rf_pred == 0)
    recovered = missed_by_rf & (iso_pred == 1)

    # Extra benign alerts introduced by IF.
    extra_benign = (
        (y == 0) & (rf_pred == 0) & (iso_pred == 1)
    )

    print("\nAdditional attacks recovered by IF:",
          int(recovered.sum()))
    print("Additional benign alerts introduced by IF:",
          int(extra_benign.sum()))

    return results

val_results = compare(
    "THURSDAY VALIDATION",
    val["is_attack"].to_numpy(),
    val_rf, val_iso, val_hybrid
)

test_results = compare(
    "FRIDAY FINAL TEST",
    test["is_attack"].to_numpy(),
    test_rf, test_iso, test_hybrid
)

print("\nPER-ATTACK FRIDAY COMPARISON")

per_attack = {}

for name in sorted(test["Label"].unique()):
    if name == "BENIGN":
        continue

    mask = test["Label"].to_numpy() == name

    per_attack[name] = {
        "samples": int(mask.sum()),
        "RF_detected": int(test_rf[mask].sum()),
        "IF_detected": int(test_iso[mask].sum()),
        "Hybrid_detected": int(test_hybrid[mask].sum()),
        "RF_recall": float(test_rf[mask].mean()),
        "IF_recall": float(test_iso[mask].mean()),
        "Hybrid_recall": float(test_hybrid[mask].mean())
    }

    print(name, per_attack[name])

report = {
    "random_forest_threshold": RF_THRESHOLD,
    "isolation_forest_threshold": if_threshold,
    "if_validation_benign_fpr_target": IF_TARGET_FPR,
    "validation": val_results,
    "friday_test": test_results,
    "friday_per_attack": per_attack,
    "note": (
        "IF threshold calibrated on Thursday BENIGN traffic. "
        "Friday used only for final evaluation."
    )
}

output = os.path.join(BACKEND, "cic_hybrid_comparison.json")

with open(output, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

print("\n" + "=" * 65)
print("COMPARISON COMPLETED")
print("Saved:", output)
print("No model files were modified.")
print("=" * 65)
