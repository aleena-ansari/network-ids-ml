import pandas as pd
from pathlib import Path
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import pandas as pd

from .database import Base, engine, SessionLocal
from .models import Alert
from .ml_utils import predict_row, get_mac_from_ip

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

    row_df = pd.DataFrame([traffic])
    result = predict_row(row_df)
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
    """List all alerts, newest first — for the SOC dashboard."""
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
    return alerts


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Single alert detail — for the investigation page."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    return alert


@app.put("/alerts/{alert_id}/status")
def update_status(alert_id: int, status: dict, db: Session = Depends(get_db)):
    """Analyst updates an alert's status (reviewed / false_positive / escalated)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    alert.status = status.get("status", alert.status)
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
