import pandas as pd
import joblib

# Load everything we saved
binary_model = joblib.load("binary_model.pkl")
category_model = joblib.load("category_model.pkl")
model_columns = joblib.load("model_columns.pkl")

# Severity weights per attack category (you can tune these)
severity_weight = {
    "dos": 0.9,
    "probe": 0.5,
    "r2l": 0.85,
    "u2r": 1.0,   # privilege escalation is the most dangerous if real
    "normal": 0.0
}

def predict_row(row_df):
    """
    row_df: a single-row DataFrame with the SAME columns as model_columns
    Returns: dict with label, category, risk_score
    """
    row_df = row_df.reindex(columns=model_columns, fill_value=0)

    # Step 1: is it normal or attack, and how confident?
    binary_proba = binary_model.predict_proba(row_df)[0]
    binary_classes = binary_model.classes_
    attack_confidence = binary_proba[list(binary_classes).index("attack")]
    label = binary_model.predict(row_df)[0]

    if label == "normal":
        return {
            "label": "normal",
            "category": "normal",
            "risk_score": round(attack_confidence * 100, 1)
        }

    # Step 2: if it IS an attack, which kind, and how confident?
    cat_proba = category_model.predict_proba(row_df)[0]
    cat_classes = category_model.classes_
    predicted_category = category_model.predict(row_df)[0]
    category_confidence = cat_proba[list(cat_classes).index(predicted_category)]

    # Risk score = how sure it's an attack * how sure of category * how severe that category is
    weight = severity_weight.get(predicted_category, 0.7)
    risk_score = attack_confidence * category_confidence * weight * 100

    return {
        "label": "attack",
        "category": predicted_category,
        "risk_score": round(risk_score, 1)
    }


# ---- Quick test using a few real rows from test.csv ----
if __name__ == "__main__":
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
    test_df = pd.read_csv("data/test.csv", names=columns)
    categorical_cols = ["protocol_type", "service", "flag"]

    sample = test_df.sample(5, random_state=1)
    sample_encoded = pd.get_dummies(sample, columns=categorical_cols)

    for i in range(len(sample)):
        row = sample_encoded.iloc[[i]]
        real_answer = sample.iloc[i]["attack_type"]
        result = predict_row(row)
        print(f"Real: {real_answer:15s} -> Predicted: {result}")