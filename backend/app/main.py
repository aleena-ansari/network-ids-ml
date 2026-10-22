import pandas as pd
import random
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import Base, engine, SessionLocal
from .models import Alert
from .ml_utils import predict_row, get_mac_from_ip
import os
import pandas as pd

from sklearn.metrics import (
    precision_score,
    recall_score,
    confusion_matrix,
    roc_auc_score
)

from . import ml_utils

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Network Intrusion Detector API")

# Allow the frontend (running on a different port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def root():
    return {"message": "Network Intrusion Detector API is running"}


@app.post("/predict")
def predict(traffic: dict, db: Session = Depends(get_db)):
    """
    Takes raw traffic feature values as JSON, runs the model,
    saves the result as an alert, and returns it.
    """
    src_ip = traffic.pop("src_ip", None)
    dst_ip = traffic.pop("dst_ip", None)

    from fastapi import HTTPException

    try:
        row_df = pd.DataFrame([traffic])
        result = predict_row(row_df)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid traffic input: {exc}"
    ) from exc
    detection_source = result.get("detection_source", "none")
    anomaly_detected = result.get("anomaly_detected", False)

    mac = get_mac_from_ip(src_ip)

    alert = Alert(
        src_ip=src_ip,
        dst_ip=dst_ip,
        mac_address=mac,
        label=result["label"],
        category=result["category"],
        risk_score=result["risk_score"],
        detection_source=detection_source,
        anomaly_detected=int(anomaly_detected),
        status="new"
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    return {
        "id": alert.id,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "mac_address": alert.mac_address,
        "label": alert.label,
        "category": alert.category,
        "risk_score": alert.risk_score,
        "detection_source": detection_source,
        "anomaly_detected": anomaly_detected,
        "status": alert.status,
        "created_at": alert.created_at
    }



@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    """List all alerts, newest first, for the SOC dashboard."""
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()

    return [
        {
            "id": alert.id,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "mac_address": alert.mac_address,
            "label": alert.label,
            "category": alert.category,
            "risk_score": float(alert.risk_score) if alert.risk_score is not None else None,
            "detection_source": alert.detection_source,
            "anomaly_detected": bool(alert.anomaly_detected),
            "status": alert.status,
            "created_at": alert.created_at
        }
        for alert in alerts
    ]



@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Single alert detail — for the investigation page."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return alert


@app.put("/alerts/{alert_id}/status")
def update_status(
    alert_id: int,
    status: dict,
    db: Session = Depends(get_db)
):
    """Update an alert's status."""

    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    allowed_statuses = {
        "new",
        "reviewed",
        "false_positive",
        "escalated"
    }

    new_status = status.get("status")

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status"
        )

    alert.status = new_status
    db.commit()
    db.refresh(alert)

    return alert


@app.post("/simulate")
def simulate(count: int = 5, db: Session = Depends(get_db)):
    """Generate demo alerts from sample NSL-KDD test traffic."""
    import random

    if count < 1 or count > 100:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="count must be between 1 and 100"
        )

    # Project root / data / test.csv
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = project_root / "data" / "test.csv"

    if not dataset_path.exists():
        from fastapi import HTTPException
        raise HTTPException(
            status_code=404,
            detail=f"Test dataset not found: {dataset_path}"
        )

    # NSL-KDD has 41 features + label + difficulty level.
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
        "label", "difficulty_level"
    ]

    # The CSV has no header row.
    data = pd.read_csv(dataset_path, header=None, names=columns)

    # Select random sample rows for the demo.
    samples = data.sample(
        n=min(count, len(data)),
        replace=(count > len(data))
    )

    created_alerts = []

    for _, sample in samples.iterrows():
        # Keep only the 41 model input features.
        traffic = sample.drop(
            labels=["label", "difficulty_level"]
        ).to_dict()

        # Simulated IPs for demonstration only.
        is_local = random.choice([True, False])

        if is_local:
            src_ip = f"192.168.1.{random.randint(2, 254)}"
        else:
            # Reserved documentation IP range.
            src_ip = f"203.0.113.{random.randint(1, 254)}"

        dst_ip = f"198.51.100.{random.randint(1, 254)}"

        # Reuse the existing prediction logic.
        row_df = pd.DataFrame([traffic])
        result = predict_row(row_df)

        mac = get_mac_from_ip(src_ip)

        alert = Alert(
            src_ip=src_ip,
            dst_ip=dst_ip,
            mac_address=mac,
            label=result["label"],
            category=result["category"],
            risk_score=result["risk_score"],
            detection_source=result.get("detection_source", "none"),
            anomaly_detected=int(result.get("anomaly_detected", False)),
            status="new"
        )

        db.add(alert)
        db.flush()

        created_alerts.append({
            "id": alert.id,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "mac_address": alert.mac_address,
            "label": alert.label,
            "category": alert.category,
            "risk_score": alert.risk_score,
            "detection_source": alert.detection_source,
            "anomaly_detected": bool(alert.anomaly_detected),
            "status": alert.status
        })

    db.commit()

    return {
        "message": f"Generated {len(created_alerts)} demo alerts",
        "count": len(created_alerts),
        "alerts": created_alerts
    }

@app.get("/metrics")
def get_metrics():
    """Evaluate the saved binary classifier on the NSL-KDD test dataset."""

    project_root = os.path.dirname(
        os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
    )
    test_path = os.path.join(project_root, "data", "test.csv")

    if not os.path.exists(test_path):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail="Test dataset not found at data/test.csv"
        )

    feature_names = [
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
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
    ]

    columns = feature_names + ["label", "difficulty"]

    try:
        test_df = pd.read_csv(
            test_path,
            header=None,
            names=columns
        )

        if test_df.empty:
            raise ValueError("The test dataset is empty.")

        # Separate features and true labels.
        X = test_df[feature_names].copy()
        labels = test_df["label"].astype(str).str.strip().str.lower()

        # NSL-KDD labels: normal stays normal; all attack types become attack.
        y_true = labels.map(
            lambda value: "normal"
            if value.rstrip(".") == "normal"
            else "attack"
        )
        
        # Match the preprocessing used in train.py
        train_path = os.path.join(project_root, "data", "train.csv")

        if not os.path.exists(train_path):
            raise ValueError("Training dataset not found at data/train.csv")

        train_df = pd.read_csv(
            train_path,
            header=None,
            names=columns
        )

        train_df["is_train"] = 1
        test_df["is_train"] = 0

        combined = pd.concat(
            [train_df, test_df],
            ignore_index=True
        )

        combined_encoded = pd.get_dummies(
            combined,
            columns=["protocol_type", "service", "flag"]
        )

        test_encoded = combined_encoded[
            combined_encoded["is_train"] == 0
        ]

        X = test_encoded.drop(
            columns=[
                "label",
                "attack_type",
                "attack_category",
                "difficulty_level",
                "difficulty",
                "is_train"
            ],
            errors="ignore"
        )

        X = X.reindex(
            columns=ml_utils.model_columns,
            fill_value=0
        )

        # Ground-truth labels: normal vs attack
        y_binary = (y_true == "attack").astype(int)

        # Random Forest probabilities
        model = ml_utils.binary_model
        probabilities = model.predict_proba(X)
        classes = list(model.classes_)
        attack_index = classes.index("attack")
        attack_probabilities = probabilities[:, attack_index]

        # Use the same 0.3 threshold as predict_row()
        rf_predictions = (attack_probabilities >= 0.3).astype(int)

        # Combined pipeline: Random Forest + Isolation Forest
        anomaly_predictions = ml_utils.isolation_model.predict(X)
        combined_predictions = (
            (rf_predictions == 1) | (anomaly_predictions == -1)
        ).astype(int)

        def calculate_metrics(y_true_binary, predictions):
            precision = precision_score(
                y_true_binary, predictions, zero_division=0
            )
            recall = recall_score(
                y_true_binary, predictions, zero_division=0
            )

            tn, fp, fn, tp = confusion_matrix(
                y_true_binary, predictions, labels=[0, 1]
            ).ravel()

            fpr = fp / (fp + tn) if (fp + tn) else 0.0

            return {
                "precision": round(float(precision), 4),
                "recall": round(float(recall), 4),
                "false_positive_rate": round(float(fpr), 4),
                "true_positives": int(tp),
                "false_positives": int(fp),
                "true_negatives": int(tn),
                "false_negatives": int(fn)
            }

        # AUC evaluates Random Forest probabilities, not final combined labels.
        auc = roc_auc_score(y_binary, attack_probabilities)

        return {
            "dataset": "NSL-KDD test.csv",
            "test_samples": int(len(test_df)),
            "actual_attacks": int(y_binary.sum()),
            "actual_normal": int((y_binary == 0).sum()),
            "evaluation_threshold": 0.3,
            "random_forest": {
                **calculate_metrics(y_binary, rf_predictions),
                "roc_auc": round(float(auc), 4)
            },
            "combined_detection_system": {
                **calculate_metrics(y_binary, combined_predictions),
                "roc_auc": None,
                "note": (
                    "ROC-AUC is not reported for the combined system "
                    "because this evaluation uses its final binary decisions. "
                    "The Random Forest probability-based AUC is reported separately."
                )
            }
        }


        y_pred = model.predict(X)
        probabilities = model.predict_proba(X)
        classes = list(model.classes_)
        attack_index = classes.index("attack")
        attack_probabilities = probabilities[:, attack_index]

        precision = precision_score(
            y_true, y_pred, pos_label="attack", zero_division=0
        )
        recall = recall_score(
            y_true, y_pred, pos_label="attack", zero_division=0
        )

        # Explicit label order: normal, attack.
        tn, fp, fn, tp = confusion_matrix(
            y_true, y_pred, labels=["normal", "attack"]
        ).ravel()

        fpr = fp / (fp + tn) if (fp + tn) else 0.0

        # ROC-AUC uses continuous probabilities, not hard predictions.
        y_binary = (y_true == "attack").astype(int)
        auc = roc_auc_score(y_binary, attack_probabilities)

        return {
            "model": "Random Forest",
            "dataset": "NSL-KDD test.csv",
            "evaluation": "Binary classification; all non-normal labels are attacks",
            "test_samples": int(len(test_df)),
            "actual_attacks": int(y_binary.sum()),
            "actual_normal": int((y_binary == 0).sum()),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "false_positive_rate": round(float(fpr), 4),
            "roc_auc": round(float(auc), 4)
        }

    except Exception as exc:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail=f"Metrics evaluation failed: {str(exc)}"
        )
