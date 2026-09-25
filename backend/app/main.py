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

    mac = get_mac_from_ip(src_ip)

    alert = Alert(
        src_ip=src_ip,
        dst_ip=dst_ip,
        mac_address=mac,
        label=result["label"],
        category=result["category"],
        risk_score=result["risk_score"],
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