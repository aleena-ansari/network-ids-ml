
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score
)

# Load saved models
binary_model = joblib.load("binary_model.pkl")
isolation_model = joblib.load("isolation_forest.pkl")
model_columns = joblib.load("model_columns.pkl")

# NSL-KDD columns
columns = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack_type", "difficulty_level"
]

# Load held-out test data
test_df = pd.read_csv(
    "data/test.csv", header=None, names=columns
)

y_true = (test_df["attack_type"] != "normal").astype(int)

# Prepare the same 41 input features
X_test = test_df.drop(
    columns=["attack_type", "difficulty_level"]
)

X_test = pd.get_dummies(
    X_test,
    columns=["protocol_type", "service", "flag"]
)

X_test = X_test.reindex(
    columns=model_columns, fill_value=0
)

# Random Forest prediction at threshold 0.3
classes = list(binary_model.classes_)
attack_index = classes.index("attack")

attack_probability = binary_model.predict_proba(X_test)[:, attack_index]
rf_pred = (attack_probability >= 0.3).astype(int)

# Isolation Forest: -1 means anomaly
iso_pred = (
    isolation_model.predict(X_test) == -1
).astype(int)

# Hybrid: either model can flag a connection
hybrid_pred = np.logical_or(
    rf_pred == 1, iso_pred == 1
).astype(int)

def report(name, predictions):
    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    precision = precision_score(
        y_true, predictions, zero_division=0
    )
    recall = recall_score(
        y_true, predictions, zero_division=0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0

    print(f"\n--- {name} ---")
    print("Confusion matrix:")
    print([[tn, fp], [fn, tp]])
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"False-positive rate: {fpr:.4f}")
    print(f"Alerts generated: {int(np.sum(predictions))}")

    return {
        "model": name,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "alerts": int(np.sum(predictions))
    }

results = [
    report("Random Forest (threshold 0.3)", rf_pred),
    report("Isolation Forest", iso_pred),
    report("Hybrid (either model flags)", hybrid_pred)
]

pd.DataFrame(results).to_csv(
    "hybrid_evaluation.csv", index=False
)

print("\nSaved results to hybrid_evaluation.csv")

# Per-attack comparison: Random Forest vs Isolation Forest vs Hybrid
print("\n========== PER-ATTACK HYBRID COMPARISON ==========")

attack_results = []

for attack_name, group in test_df.groupby("attack_type"):
    if attack_name == "normal":
        continue

    idx = group.index

    total = len(idx)
    rf_caught = int(rf_pred[idx].sum())
    iso_caught = int(iso_pred[idx].sum())
    hybrid_caught = int(hybrid_pred[idx].sum())

    attack_results.append({
        "attack_type": attack_name,
        "total": total,
        "rf_detected": rf_caught,
        "rf_detection_rate": round(rf_caught / total, 4),
        "iso_detected": iso_caught,
        "iso_detection_rate": round(iso_caught / total, 4),
        "hybrid_detected": hybrid_caught,
        "hybrid_detection_rate": round(
            hybrid_caught / total, 4
        ),
        "extra_detected_by_hybrid": hybrid_caught - rf_caught
    })

per_attack = pd.DataFrame(attack_results)
per_attack = per_attack.sort_values(
    "hybrid_detection_rate"
)

print(per_attack.to_string(index=False))

per_attack.to_csv(
    "hybrid_per_attack.csv", index=False
)

print("\nSaved per-attack comparison to hybrid_per_attack.csv")
