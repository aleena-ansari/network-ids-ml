import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

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

# Group the ~22 individual attack types into 4 standard NSL-KDD categories
# This is the widely-used standard grouping for this dataset
attack_map = {
    "normal": "normal",
    "neptune": "dos", "back": "dos", "land": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "mailbomb": "dos", "apache2": "dos",
    "processtable": "dos", "udpstorm": "dos",
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe", "satan": "probe",
    "mscan": "probe", "saint": "probe",
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l", "multihop": "r2l",
    "phf": "r2l", "spy": "r2l", "warezclient": "r2l", "warezmaster": "r2l",
    "sendmail": "r2l", "named": "r2l", "snmpgetattack": "r2l", "snmpguess": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "worm": "r2l",
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r", "rootkit": "u2r",
    "httptunnel": "u2r", "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r"
}

def load_and_prepare(path):
    df = pd.read_csv(path, names=columns)
    df["label"] = df["attack_type"].apply(lambda x: "normal" if x == "normal" else "attack")
    df["attack_category"] = df["attack_type"].map(attack_map).fillna("unknown")
    return df

train_df = load_and_prepare("data/train.csv")
test_df = load_and_prepare("data/test.csv")

train_df["is_train"] = 1
test_df["is_train"] = 0
combined = pd.concat([train_df, test_df], axis=0)

categorical_cols = ["protocol_type", "service", "flag"]
combined_encoded = pd.get_dummies(combined, columns=categorical_cols)

train_encoded = combined_encoded[combined_encoded["is_train"] == 1]
test_encoded = combined_encoded[combined_encoded["is_train"] == 0]

drop_cols = ["label", "attack_type", "attack_category", "difficulty_level", "is_train"]
X_train = train_encoded.drop(columns=drop_cols)
y_train_binary = train_encoded["label"]
X_test = test_encoded.drop(columns=drop_cols)
y_test_binary = test_encoded["label"]

# ---------- MODEL 1: normal vs attack ----------
print("Training binary model (normal vs attack)...")
binary_model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
binary_model.fit(X_train, y_train_binary)

y_pred_binary = binary_model.predict(X_test)
print("\n--- Binary Model Results ---")
print(classification_report(y_test_binary, y_pred_binary))
print(confusion_matrix(y_test_binary, y_pred_binary))

# ---------- MODEL 2: attack category (dos/probe/r2l/u2r) ----------
# Trained only on rows that ARE attacks
train_attack_only = train_encoded[train_encoded["label"] == "attack"]
test_attack_only = test_encoded[test_encoded["label"] == "attack"]

X_train_cat = train_attack_only.drop(columns=drop_cols)
y_train_cat = train_attack_only["attack_category"]
X_test_cat = test_attack_only.drop(columns=drop_cols)
y_test_cat = test_attack_only["attack_category"]

print("\nTraining attack-category model (dos/probe/r2l/u2r)...")
category_model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
category_model.fit(X_train_cat, y_train_cat)

y_pred_cat = category_model.predict(X_test_cat)
print("\n--- Attack Category Model Results ---")
print(classification_report(y_test_cat, y_pred_cat))
print(confusion_matrix(y_test_cat, y_pred_cat))

# Save both models + the column list (needed later by backend)
joblib.dump(binary_model, "binary_model.pkl")
joblib.dump(category_model, "category_model.pkl")
joblib.dump(list(X_train.columns), "model_columns.pkl")
print("\nSaved: binary_model.pkl, category_model.pkl, model_columns.pkl")