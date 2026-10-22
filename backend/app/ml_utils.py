import pandas as pd
import joblib
import os
import subprocess
import re
import ipaddress

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

binary_model = joblib.load(os.path.join(BASE_DIR, "binary_model.pkl"))
category_model = joblib.load(os.path.join(BASE_DIR, "category_model.pkl"))
isolation_model = joblib.load(os.path.join(BASE_DIR, "isolation_forest.pkl"))
model_columns = joblib.load(os.path.join(BASE_DIR, "model_columns.pkl"))

severity_weight = {
    "dos": 0.9,
    "probe": 0.5,
    "r2l": 0.85,
    "u2r": 1.0,
    "normal": 0.0
}



def predict_row(row_df: pd.DataFrame) -> dict:
    # Ensure the features match the training column order
    row_df = row_df.reindex(columns=model_columns, fill_value=0)

    # Model 1: supervised Random Forest
    binary_proba = binary_model.predict_proba(row_df)[0]
    binary_classes = list(binary_model.classes_)
    attack_confidence = float(
        binary_proba[binary_classes.index("attack")]
    )

    threshold = 0.3
    label = "attack" if attack_confidence >= threshold else "normal"

    # Model 2: Isolation Forest
    # -1 means anomaly; +1 means inlier
    anomaly_prediction = int(isolation_model.predict(row_df)[0])
    is_anomaly = anomaly_prediction == -1

    # If Random Forest flags an attack, classify its category
    if label == "attack":
        cat_proba = category_model.predict_proba(row_df)[0]
        cat_classes = list(category_model.classes_)
        predicted_category = category_model.predict(row_df)[0]

        category_confidence = float(
            cat_proba[cat_classes.index(predicted_category)]
        )

        weight = severity_weight.get(predicted_category, 0.7)
        risk_score = (
            attack_confidence * category_confidence * weight * 100
        )

        return {
            "label": "attack",
            "category": predicted_category,
            "risk_score": round(float(risk_score), 1),
            "detection_source": "random_forest",
            "anomaly_detected": is_anomaly
        }

    # Random Forest says normal, but Isolation Forest flags unusual traffic
    if is_anomaly:
        return {
            "label": "attack",
            "category": "anomaly",
            "risk_score": 50.0,
            "detection_source": "isolation_forest",
            "anomaly_detected": True
        }

    # Neither model flags the traffic
    return {
        "label": "normal",
        "category": "normal",
        "risk_score": round(attack_confidence * 100, 1),
        "detection_source": "none",
        "anomaly_detected": False
    }


def is_local_ip(ip: str) -> bool:
    """Check whether an IP belongs to a private IPv4 network or loopback."""
    if not ip:
        return False

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if not isinstance(address, ipaddress.IPv4Address):
        return False

    return (
        address.is_loopback
        or address in ipaddress.ip_network("10.0.0.0/8")
        or address in ipaddress.ip_network("172.16.0.0/12")
        or address in ipaddress.ip_network("192.168.0.0/16")
    )


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