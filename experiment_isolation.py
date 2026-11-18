import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

DATA_DIR = "data/cicids_ready"
MODEL_DIR = "backend"
CHUNK_SIZE = 50000

print("=" * 65)
print("SENTRYNET - ISOLATION FOREST IMPROVEMENT EXPERIMENT")
print("=" * 65)

# Load the existing model and exact feature order.
model = joblib.load(
    os.path.join(MODEL_DIR, "cic_isolation_model.pkl")
)
columns = joblib.load(
    os.path.join(MODEL_DIR, "cic_columns.pkl")
)

def load_scores(path):
    all_scores = []
    all_labels = []
    all_attack = []

    print("\nScoring:", path)

    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE):
        missing = set(columns) - set(chunk.columns)
        if missing:
            raise ValueError(f"Missing features: {missing}")

        X = chunk[columns].astype(np.float32)

        if not np.isfinite(X.to_numpy()).all():
            raise ValueError("Invalid feature values found.")

        # Lower score means more anomalous.
        scores = model.score_samples(X)

        all_scores.append(scores)
        all_labels.extend(chunk["Label"].astype(str).tolist())
        all_attack.append(chunk["is_attack"].to_numpy())

    return (
        np.concatenate(all_scores),
        np.array(all_labels, dtype=str),
        np.concatenate(all_attack)
    )

# Score validation first.
val_scores, val_labels, val_y = load_scores(
    os.path.join(DATA_DIR, "validation.csv")
)

# Set thresholds using ONLY benign Thursday scores.
benign_scores = val_scores[val_y == 0]

if len(benign_scores) == 0:
    raise ValueError("No BENIGN validation records found.")

# Score Friday once, after defining the threshold candidates.
test_scores, test_labels, test_y = load_scores(
    os.path.join(DATA_DIR, "test.csv")
)

def calculate_metrics(y_true, predictions):
    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    return {
        "precision": float(precision_score(
            y_true, predictions, zero_division=0
        )),
        "recall": float(recall_score(
            y_true, predictions, zero_division=0
        )),
        "f1_score": float(f1_score(
            y_true, predictions, zero_division=0
        )),
        "false_positive_rate": float(
            fp / (fp + tn) if (fp + tn) else 0
        ),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp)
    }

targets = [0.005, 0.01, 0.02, 0.04]
report = {
    "method": "Isolation Forest score_samples thresholds",
    "threshold_source": "Thursday BENIGN validation records only",
    "results": {}
}

print("\n" + "=" * 65)
print("THRESHOLD COMPARISON")
print("=" * 65)

for target in targets:
    # Lower score = more anomalous.
    threshold = float(np.quantile(benign_scores, target))

    val_pred = (val_scores <= threshold).astype(int)
    test_pred = (test_scores <= threshold).astype(int)

    val_metrics = calculate_metrics(val_y, val_pred)
    test_metrics = calculate_metrics(test_y, test_pred)

    per_attack = {}

    for name in sorted(set(test_labels)):
        if name == "BENIGN":
            continue

        mask = test_labels == name
        per_attack[name] = {
            "samples": int(mask.sum()),
            "detected": int(test_pred[mask].sum()),
            "detection_rate": float(test_pred[mask].mean())
        }

    key = f"{target * 100:.1f}%"

    report["results"][key] = {
        "score_threshold": threshold,
        "validation": val_metrics,
        "friday_test": test_metrics,
        "friday_per_attack": per_attack
    }

    print(f"\nTarget validation BENIGN FPR: {key}")
    print("Score threshold:", threshold)
    print("Validation:", val_metrics)
    print("Friday:", test_metrics)

    print("Friday attack detection:")
    for name, values in per_attack.items():
        print(
            f"  {name}: {values['detected']:,}/"
            f"{values['samples']:,} "
            f"({values['detection_rate']:.2%})"
        )

# Predeclared operating point: 1% validation BENIGN FPR.
selected = report["results"]["1.0%"]
report["selected_operating_point"] = "1.0%"
report["selected_score_threshold"] = selected["score_threshold"]
report["selected_friday_results"] = selected["friday_test"]
report["selected_friday_per_attack"] = selected["friday_per_attack"]

output = os.path.join(MODEL_DIR, "if_experiment_results.json")

with open(output, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

print("\n" + "=" * 65)
print("EXPERIMENT COMPLETED")
print("=" * 65)
print("Selected operating point: 1% validation BENIGN FPR")
print("Results saved to:", output)
print("No model files were modified.")
