import pandas as pd
import joblib
import os
import subprocess
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

binary_model = joblib.load(os.path.join(BASE_DIR, "binary_model.pkl"))
category_model = joblib.load(os.path.join(BASE_DIR, "category_model.pkl"))
model_columns = joblib.load(os.path.join(BASE_DIR, "model_columns.pkl"))

severity_weight = {
    "dos": 0.9,
    "probe": 0.5,
    "r2l": 0.85,
    "u2r": 1.0,
    "normal": 0.0
}


def predict_row(row_df: pd.DataFrame) -> dict:
    row_df = row_df.reindex(columns=model_columns, fill_value=0)

    binary_proba = binary_model.predict_proba(row_df)[0]
    binary_classes = list(binary_model.classes_)
    attack_confidence = float(binary_proba[binary_classes.index("attack")])
    label = binary_model.predict(row_df)[0]

    if label == "normal":
        return {
            "label": "normal",
            "category": "normal",
            "risk_score": round(attack_confidence * 100, 1)
        }

    cat_proba = category_model.predict_proba(row_df)[0]
    cat_classes = list(category_model.classes_)
    predicted_category = category_model.predict(row_df)[0]
    category_confidence = float(cat_proba[cat_classes.index(predicted_category)])

    weight = severity_weight.get(predicted_category, 0.7)
    risk_score = attack_confidence * category_confidence * weight * 100

    return {
        "label": "attack",
        "category": predicted_category,
        "risk_score": round(float(risk_score), 1)
    }


def is_local_ip(ip: str) -> bool:
    """Check if an IP address is within common private/local network ranges."""
    if not ip:
        return False
    private_patterns = [
        r"^10\.",
        r"^192\.168\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^127\."
    ]
    return any(re.match(pattern, ip) for pattern in private_patterns)


def get_mac_from_ip(ip: str):
    """
    Look up MAC address from the ARP table for a local IP.
    Returns None if IP is not local or not found.
    """
    if not is_local_ip(ip):
        return None

    try:
        result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3)
        match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", result.stdout)
        if match:
            return match.group(0)
    except Exception:
        pass

    return None