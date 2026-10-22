
import pandas as pd
import joblib

# Original column names used by train.py
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack_type", "difficulty_level"
]

# Reproduce train.py's preprocessing
train = pd.read_csv("data/train.csv", header=None, names=columns)
test = pd.read_csv("data/test.csv", header=None, names=columns)

train["label"] = train["attack_type"].apply(
    lambda value: "normal" if value == "normal" else "attack"
)
test["label"] = test["attack_type"].apply(
    lambda value: "normal" if value == "normal" else "attack"
)

train["attack_category"] = "unused"
test["attack_category"] = "unused"

train["is_train"] = 1
test["is_train"] = 0

combined = pd.concat([train, test], ignore_index=True)

encoded = pd.get_dummies(
    combined,
    columns=["protocol_type", "service", "flag"]
)

test_encoded = encoded[encoded["is_train"] == 0]

drop_cols = [
    "label", "attack_type", "attack_category",
    "difficulty_level", "is_train"
]

X_reference = test_encoded.drop(columns=drop_cols)

# Reproduce the current /metrics preprocessing
metrics_columns = columns[:41] + ["label", "difficulty"]
train_metrics = pd.read_csv(
    "data/train.csv", header=None, names=metrics_columns
)
test_metrics = pd.read_csv(
    "data/test.csv", header=None, names=metrics_columns
)

train_metrics["is_train"] = 1
test_metrics["is_train"] = 0

metrics_combined = pd.concat(
    [train_metrics, test_metrics], ignore_index=True
)

metrics_encoded = pd.get_dummies(
    metrics_combined,
    columns=["protocol_type", "service", "flag"]
)

metrics_test = metrics_encoded[
    metrics_encoded["is_train"] == 0
]

X_metrics = metrics_test.drop(
    columns=[
        "label", "attack_type", "attack_category",
        "difficulty_level", "difficulty", "is_train"
    ],
    errors="ignore"
)

# Align both matrices to the saved model feature order
model_columns = joblib.load("backend/model_columns.pkl")

X_reference = X_reference.reindex(
    columns=model_columns, fill_value=0
)
X_metrics = X_metrics.reindex(
    columns=model_columns, fill_value=0
)

print("Reference shape:", X_reference.shape)
print("Metrics shape:", X_metrics.shape)
print("Same feature order:", list(X_reference.columns) == list(X_metrics.columns))
print("Same feature values:", X_reference.equals(X_metrics))
print("Different values:", int((X_reference != X_metrics).to_numpy().sum()))
