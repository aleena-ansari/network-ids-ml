
import pandas as pd
import joblib

from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score
)

# 1. Load the saved models and feature columns
isolation_model = joblib.load("isolation_forest.pkl")
binary_model = joblib.load("binary_model.pkl")
model_columns = joblib.load("model_columns.pkl")

# 2. Define the NSL-KDD columns
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

# 3. Load the held-out test dataset
test_df = pd.read_csv("data/test.csv", header=None, names=columns)

# Binary ground truth: 1 = attack, 0 = normal
y_true = (test_df["attack_type"] != "normal").astype(int)

# 4. Prepare features exactly as during training
categorical_cols = ["protocol_type", "service", "flag"]

X_test = test_df.drop(
    columns=["attack_type", "difficulty_level"]
)

X_test = pd.get_dummies(
    X_test,
    columns=categorical_cols
)

X_test = X_test.reindex(
    columns=model_columns,
    fill_value=0
)

# 5. Evaluate Isolation Forest
# Isolation Forest: -1 = anomaly, +1 = inlier
isolation_predictions = isolation_model.predict(X_test)

# Convert anomaly predictions into 1 = attack-like
y_iso = (isolation_predictions == -1).astype(int)

print("\n========== ISOLATION FOREST ==========")
print("Test rows:", len(y_true))
print("Anomalies flagged:", int(y_iso.sum()))

print("Confusion matrix:")
print(confusion_matrix(y_true, y_iso, labels=[0, 1]))

print("Precision:", round(precision_score(
    y_true, y_iso, zero_division=0
), 4))

print("Recall:", round(recall_score(
    y_true, y_iso, zero_division=0
), 4))

tn, fp, fn, tp = confusion_matrix(
    y_true, y_iso, labels=[0, 1]
).ravel()

fpr = fp / (fp + tn) if (fp + tn) else 0
print("False-positive rate:", round(fpr, 4))

# 6. Compare with the supervised Random Forest at threshold 0.3
binary_classes = list(binary_model.classes_)
attack_index = binary_classes.index("attack")

attack_probability = binary_model.predict_proba(X_test)[:, attack_index]
y_rf = (attack_probability >= 0.3).astype(int)

# Attacks missed by Random Forest
rf_missed = (y_true == 1) & (y_rf == 0)

# Of those missed attacks, how many does Isolation Forest flag?
missed_count = int(rf_missed.sum())
recovered_count = int((rf_missed & (y_iso == 1)).sum())

print("\n========== HYBRID COMPARISON ==========")
print("Attacks missed by Random Forest:", missed_count)
print("Those flagged by Isolation Forest:", recovered_count)

recovery_rate = (
    recovered_count / missed_count if missed_count else 0
)
print("Recovery rate:", round(recovery_rate, 4))

# 7. Per-attack detection
print("\n========== PER-ATTACK DETECTION ==========")

results = []

for attack_name, group in test_df.groupby("attack_type"):
    if attack_name == "normal":
        continue

    indexes = group.index
    total = len(indexes)
    caught = int(y_iso[indexes].sum())

    results.append({
        "attack_type": attack_name,
        "total": total,
        "flagged": caught,
        "detection_rate": round(caught / total, 4)
    })

attack_results = pd.DataFrame(results)
attack_results = attack_results.sort_values("detection_rate")

print(attack_results.to_string(index=False))

# Save the results
attack_results.to_csv(
    "isolation_attack_results.csv",
    index=False
)

print("\nSaved per-attack results to isolation_attack_results.csv")
