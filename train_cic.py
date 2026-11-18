import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score,
    f1_score, roc_auc_score
)

# --------------------------------------------------
# SENTRYNET - CICIDS2017 MODEL TRAINING
# --------------------------------------------------

DATA_DIR = "data/cicids_ready"
MODEL_DIR = "backend"
CHUNK_SIZE = 100_000
RANDOM_STATE = 42

os.makedirs(MODEL_DIR, exist_ok=True)

print("=" * 65)
print("SENTRYNET - CICIDS2017 MODEL TRAINING")
print("=" * 65)

# Load datasets
print("\n1. Loading datasets...")

train_df = pd.read_csv(os.path.join(DATA_DIR, "train.csv"))
val_df = pd.read_csv(os.path.join(DATA_DIR, "validation.csv"))
test_df = pd.read_csv(os.path.join(DATA_DIR, "test.csv"))

excluded = ["Label", "is_attack", "source_day"]

feature_columns = [
    c for c in train_df.columns if c not in excluded
]

if not feature_columns:
    raise ValueError("No model features found.")

for name, df in [
    ("Training", train_df),
    ("Validation", val_df),
    ("Test", test_df)
]:
    missing = set(feature_columns) - set(df.columns)
    if missing:
        raise ValueError(f"{name} is missing features: {missing}")

    if df[feature_columns].isna().any().any():
        raise ValueError(f"{name} contains missing feature values.")

    if not np.isfinite(
        df[feature_columns].to_numpy(dtype=np.float32)
    ).all():
        raise ValueError(f"{name} contains infinite feature values.")

    if not set(df["is_attack"].unique()).issubset({0, 1}):
        raise ValueError(f"{name} has invalid binary labels.")

print("Training rows:", f"{len(train_df):,}")
print("Validation rows:", f"{len(val_df):,}")
print("Test rows:", f"{len(test_df):,}")
print("Features:", len(feature_columns))

# Use float32 to reduce memory use.
X_train = train_df[feature_columns].astype(np.float32)
y_train = train_df["is_attack"].astype("int8")

X_val = val_df[feature_columns].astype(np.float32)
y_val = val_df["is_attack"].astype("int8")

X_test = test_df[feature_columns].astype(np.float32)
y_test = test_df["is_attack"].astype("int8")

# --------------------------------------------------
# 2. CONTROL CLASS IMBALANCE
# --------------------------------------------------

print("\n2. Preparing balanced training sample...")

normal_indices = y_train[y_train == 0].index
attack_indices = y_train[y_train == 1].index

rng = np.random.RandomState(RANDOM_STATE)

normal_sample_size = min(300_000, len(normal_indices))

selected_normal = rng.choice(
    normal_indices.to_numpy(),
    size=normal_sample_size,
    replace=False
)

selected_indices = np.concatenate([
    selected_normal,
    attack_indices.to_numpy()
])

rng.shuffle(selected_indices)

X_fit = X_train.loc[selected_indices]
y_fit = y_train.loc[selected_indices]

print("Normal records selected:", f"{normal_sample_size:,}")
print("Attack records selected:", f"{len(attack_indices):,}")
print("Total model training records:", f"{len(X_fit):,}")

# --------------------------------------------------
# 3. TRAIN RANDOM FOREST
# --------------------------------------------------

print("\n3. Training Random Forest...")

binary_model = RandomForestClassifier(
    n_estimators=60,
    max_depth=20,
    min_samples_leaf=5,
    class_weight="balanced_subsample",
    max_samples=0.8,
    random_state=RANDOM_STATE,
    n_jobs=-1
)

binary_model.fit(X_fit, y_fit)

print("Random Forest training completed.")

# --------------------------------------------------
# 4. TRAIN ISOLATION FOREST ON BENIGN TRAFFIC
# --------------------------------------------------

print("\n4. Training Isolation Forest...")

normal_data = X_train[y_train == 0]

iso_sample_size = min(100_000, len(normal_data))

iso_sample = normal_data.sample(
    n=iso_sample_size,
    random_state=RANDOM_STATE
)

isolation_model = Pipeline([
    ("scaler", StandardScaler()),
    ("isolation_forest", IsolationForest(
        n_estimators=100,
        contamination=0.02,
        random_state=RANDOM_STATE,
        n_jobs=-1
    ))
])

isolation_model.fit(iso_sample)

print("Isolation Forest training completed.")
print("Normal records used:", f"{iso_sample_size:,}")

# --------------------------------------------------
# 5. HELPER FUNCTIONS
# --------------------------------------------------

def get_attack_probability(model, X):
    attack_index = list(model.classes_).index(1)
    return model.predict_proba(X)[:, attack_index]


def get_iso_predictions(model, X):
    return (model.predict(X) == -1).astype(int)


def calculate_metrics(y_true, predictions, probabilities=None):
    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    result = {
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
        "true_positives": int(tp),
        "alerts": int(np.sum(predictions))
    }

    if probabilities is not None:
        result["roc_auc"] = float(
            roc_auc_score(y_true, probabilities)
        )

    return result


# --------------------------------------------------
# 6. SELECT THRESHOLD USING THURSDAY VALIDATION
# --------------------------------------------------

print("\n5. Selecting threshold using validation data...")

val_probability = get_attack_probability(binary_model, X_val)

threshold_results = {}

for threshold in [0.1, 0.2, 0.3, 0.4, 0.5]:
    val_prediction = (
        val_probability >= threshold
    ).astype(int)

    threshold_results[str(threshold)] = calculate_metrics(
        y_val, val_prediction, val_probability
    )

    m = threshold_results[str(threshold)]

    print(
        f"Threshold {threshold:.1f} | "
        f"Precision {m['precision']:.4f} | "
        f"Recall {m['recall']:.4f} | "
        f"FPR {m['false_positive_rate']:.4f} | "
        f"F1 {m['f1_score']:.4f}"
    )

# Select the threshold with highest validation F1.
# In case of ties, prefer the higher threshold.
best_threshold = max(
    [0.1, 0.2, 0.3, 0.4, 0.5],
    key=lambda t: (
        threshold_results[str(t)]["f1_score"], t
    )
)

print("\nSelected threshold:", best_threshold)

# --------------------------------------------------
# 7. VALIDATION HYBRID EVALUATION
# --------------------------------------------------

print("\n6. Evaluating models on validation data...")

val_rf = (val_probability >= best_threshold).astype(int)
val_iso = get_iso_predictions(isolation_model, X_val)
val_hybrid = np.logical_or(val_rf, val_iso).astype(int)

validation_results = {
    "random_forest": calculate_metrics(
        y_val, val_rf, val_probability
    ),
    "isolation_forest": calculate_metrics(
        y_val, val_iso
    ),
    "hybrid": calculate_metrics(
        y_val, val_hybrid
    )
}

# --------------------------------------------------
# 8. FINAL FRIDAY TEST
# --------------------------------------------------

print("\n7. Evaluating on unseen Friday test data...")

test_probability = get_attack_probability(binary_model, X_test)

test_rf = (
    test_probability >= best_threshold
).astype(int)

test_iso = get_iso_predictions(isolation_model, X_test)

test_hybrid = np.logical_or(
    test_rf, test_iso
).astype(int)

test_results = {
    "random_forest": calculate_metrics(
        y_test, test_rf, test_probability
    ),
    "isolation_forest": calculate_metrics(
        y_test, test_iso
    ),
    "hybrid": calculate_metrics(
        y_test, test_hybrid
    )
}

for model_name, metrics in test_results.items():
    print(f"\n--- {model_name.upper()} ---")
    for metric, value in metrics.items():
        print(f"{metric}: {value}")

# --------------------------------------------------
# 9. PER-ATTACK DETECTION ON FRIDAY
# --------------------------------------------------

print("\n8. Per-attack detection results...")

per_attack = {}

for attack_name, group in test_df.groupby("Label"):
    if attack_name == "BENIGN":
        continue

    indexes = group.index.to_numpy()

    per_attack[str(attack_name)] = {
        "samples": int(len(indexes)),
        "random_forest_detected": int(test_rf[indexes].sum()),
        "isolation_forest_detected": int(test_iso[indexes].sum()),
        "hybrid_detected": int(test_hybrid[indexes].sum()),
        "random_forest_recall": float(test_rf[indexes].mean()),
        "isolation_forest_recall": float(test_iso[indexes].mean()),
        "hybrid_recall": float(test_hybrid[indexes].mean())
    }

    print(
        attack_name,
        "| RF:", f"{per_attack[str(attack_name)]['random_forest_recall']:.4f}",
        "| IF:", f"{per_attack[str(attack_name)]['isolation_forest_recall']:.4f}",
        "| Hybrid:", f"{per_attack[str(attack_name)]['hybrid_recall']:.4f}"
    )

# --------------------------------------------------
# 10. SAVE NEW MODEL ARTIFACTS
# --------------------------------------------------

print("\n9. Saving CICIDS2017 models...")

joblib.dump(
    binary_model,
    os.path.join(MODEL_DIR, "cic_binary_model.pkl"),
    compress=3
)

joblib.dump(
    isolation_model,
    os.path.join(MODEL_DIR, "cic_isolation_model.pkl"),
    compress=3
)

joblib.dump(
    feature_columns,
    os.path.join(MODEL_DIR, "cic_columns.pkl")
)

# Save evaluation results.
report = {
    "dataset": "CICIDS2017",
    "training_days": "Monday-Wednesday",
    "validation_day": "Thursday",
    "test_day": "Friday",
    "training_samples_used": int(len(X_fit)),
    "isolation_forest_normal_samples": int(iso_sample_size),
    "feature_count": int(len(feature_columns)),
    "selected_threshold": float(best_threshold),
    "threshold_validation_results": threshold_results,
    "validation_results": validation_results,
    "friday_test_results": test_results,
    "per_attack_results": per_attack,
    "note": (
        "Friday contains attack families absent from training. "
        "Per-family scores measure binary detection, not family classification. "
        "Threshold was selected using Thursday validation only."
    )
}

with open(
    os.path.join(MODEL_DIR, "cic_metrics.json"),
    "w",
    encoding="utf-8"
) as f:
    json.dump(report, f, indent=4)

print("\n" + "=" * 65)
print("SENTRYNET TRAINING COMPLETED")
print("=" * 65)

print("Saved model files:")
print("backend/cic_binary_model.pkl")
print("backend/cic_isolation_model.pkl")
print("backend/cic_columns.pkl")
print("backend/cic_metrics.json")

print("\nSelected threshold:", best_threshold)
print("Old NSL-KDD model files were not modified.")
