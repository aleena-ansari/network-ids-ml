import pandas as pd
import joblib
from sklearn.metrics import confusion_matrix, roc_auc_score

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","attack_type","difficulty_level"
]

# Load the saved model and the column order it expects
binary_model = joblib.load("backend/binary_model.pkl")
model_columns = joblib.load("backend/model_columns.pkl")

# Load the unseen test data
df = pd.read_csv("data/test.csv", names=columns)
y_true = (df["attack_type"] != "normal").astype(int)   # 1 = attack, 0 = normal

X = pd.get_dummies(
    df.drop(columns=["attack_type", "difficulty_level"]),
    columns=["protocol_type", "service", "flag"],
)
X = X.reindex(columns=model_columns, fill_value=0)

# Probability that each row is an attack
attack_idx = list(binary_model.classes_).index("attack")
proba = binary_model.predict_proba(X)[:, attack_idx]

# ---- 1. AUC ----
print("AUC-ROC:", round(roc_auc_score(y_true, proba), 4))

# ---- 2. Precision / recall / false-positive rate at different thresholds ----
print("\nThreshold | Precision | Recall | False-positive rate")
for t in [0.5, 0.4, 0.3, 0.2, 0.1]:
    pred = (proba >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
    print(f"   {t:.1f}    |   {tp/(tp+fp):.2f}    |  {tp/(tp+fn):.2f}  |  {fp/(fp+tn):.3f}")

# ---- 3. Which attack types does it catch or miss? (threshold 0.5) ----
df["caught"] = (proba >= 0.5).astype(int)
per_attack = (
    df[df["attack_type"] != "normal"]
    .groupby("attack_type")["caught"]
    .agg(["mean", "count"])
    .sort_values("mean")
)
per_attack["mean"] = (per_attack["mean"] * 100).round(1)
print("\nDetection rate per attack type (%), worst first:")
print(per_attack.rename(columns={"mean": "caught_%", "count": "rows"}))