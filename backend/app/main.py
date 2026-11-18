import json
from datetime import timezone
import random
from pathlib import Path

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from . import cic_utils
from .database import Base, SessionLocal, engine
from .models import Alert
from .net_utils import is_local_ip, resolve_mac

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEMO_FILE = BACKEND_DIR / "demo_flows.csv"
METRICS_FILE = BACKEND_DIR / "cic_metrics.json"
ALLOWED_STATUSES = {"new", "reviewed", "false_positive", "escalated"}

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SentryNet API (CICIDS2017)")

# Prototype setting: open CORS so the React dev server can call this API.
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


def utc_iso(dt):
    # SQLite drops the timezone. Stored times are UTC, so say so explicitly (+00:00).
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def alert_to_dict(a: Alert) -> dict:
    if a.mac_address:
        mac_note = None
    elif is_local_ip(a.src_ip):
        mac_note = "Not found - local source, MAC not observed"
    else:
        mac_note = "Not available - external source"
    return {
        "id": a.id,
        "src_ip": a.src_ip,
        "dst_ip": a.dst_ip,
        "mac_address": a.mac_address,
        "mac_note": mac_note,
        "label": a.label,
        "category": a.category,
        "attack_probability": a.attack_probability,
        "risk_score": float(a.risk_score) if a.risk_score is not None else None,
        "anomaly_score": a.anomaly_score,
        "anomaly_detected": bool(a.anomaly_detected),
        "detection_source": a.detection_source,
        "origin": a.origin,
        "status": a.status,
        "created_at": utc_iso(a.created_at),
    }


def make_alert(result: dict, src_ip, dst_ip, mac, origin: str) -> Alert:
    return Alert(
        src_ip=None if src_ip is None else str(src_ip),
        dst_ip=None if dst_ip is None else str(dst_ip),
        mac_address=mac,
        label=result["label"],
        category=result["category"],
        attack_probability=result["attack_probability"],
        risk_score=result["risk_score"],
        anomaly_score=result["anomaly_score"],
        anomaly_detected=int(result["anomaly_detected"]),
        detection_source=result["detection_source"],
        origin=origin,
        status="new",
    )


@app.get("/")
def root():
    return {"message": "SentryNet API is running (CICIDS2017 models)", "model": cic_utils.model_info()}


@app.get("/features")
def features():
    """The exact 78 feature names, in the order the models expect."""
    return {"count": len(cic_utils.feature_columns), "features": cic_utils.feature_columns}


@app.post("/predict")
def predict(traffic: dict, db: Session = Depends(get_db)):
    """
    Body: the 78 CICIDS2017 flow features (see GET /features), plus optional
    src_ip, dst_ip and src_mac. Missing or invalid features are rejected, never guessed.
    """
    payload = dict(traffic)
    src_ip = payload.pop("src_ip", None)
    dst_ip = payload.pop("dst_ip", None)
    src_mac = payload.pop("src_mac", None)

    try:
        result = cic_utils.predict_flow(payload)
        mac = resolve_mac(src_ip, src_mac)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid traffic input: {exc}") from exc

    alert = make_alert(result, src_ip, dst_ip, mac, origin="api")
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert_to_dict(alert)


@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc(), Alert.id.desc()).all()
    return [alert_to_dict(a) for a in alerts]


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert)


@app.put("/alerts/{alert_id}/status")
def update_status(alert_id: int, status: dict, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    new_status = status.get("status")
    if new_status not in ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")
    alert.status = new_status
    db.commit()
    db.refresh(alert)
    return alert_to_dict(alert)


def fake_local_mac() -> str:
    # 02:... is the "locally administered" range, so it cannot be a real vendor MAC.
    return "02:00:00:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))


@app.post("/simulate")
def simulate(count: int = 5, db: Session = Depends(get_db)):
    """
    DEMO ONLY: replay real CICIDS2017 Friday flows (backend/demo_flows.csv) with made-up IPs.
    The alerts are stored with origin = "simulated". This is not live traffic.
    """
    if count < 1 or count > 100:
        raise HTTPException(status_code=400, detail="count must be between 1 and 100")
    if not DEMO_FILE.exists():
        raise HTTPException(status_code=404, detail="backend/demo_flows.csv not found. Run make_demo_sample.py from the project root.")

    demo = pd.read_csv(DEMO_FILE)
    sample = demo.sample(n=count, replace=count > len(demo))
    true_labels = sample["Label"].astype(str).tolist()
    records = sample[cic_utils.feature_columns].to_dict("records")

    try:
        results = cic_utils.predict_flows(records)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=f"Demo data problem: {exc}") from exc

    created = []
    for result, true_label in zip(results, true_labels):
        if random.random() < 0.5:
            src_ip = f"192.168.1.{random.randint(2, 254)}"      # pretend local device
        else:
            src_ip = f"203.0.113.{random.randint(1, 254)}"      # reserved documentation range
        dst_ip = f"192.168.1.{random.randint(2, 254)}"
        mac = resolve_mac(src_ip, fake_local_mac())             # None for the external IPs

        alert = make_alert(result, src_ip, dst_ip, mac, origin="simulated")
        db.add(alert)
        db.flush()
        item = alert_to_dict(alert)
        item["true_label"] = true_label   # shown here only; not stored, not predicted by the model
        created.append(item)

    db.commit()
    return {
        "message": f"Generated {len(created)} simulated alerts",
        "note": "Replay of real CICIDS2017 Friday flows with made-up IPs/MACs. true_label is for the demo only.",
        "count": len(created),
        "alerts": created,
    }


@app.get("/metrics")
def get_metrics():
    """Saved offline evaluation (not recomputed on each request)."""
    if not METRICS_FILE.exists():
        raise HTTPException(status_code=404, detail="backend/cic_metrics.json not found")
    with open(METRICS_FILE, encoding="utf-8") as f:
        saved = json.load(f)
    return {
        "source": "backend/cic_metrics.json (offline evaluation; Friday = final test day)",
        "operating_point": cic_utils.model_info(),
        "results": saved,
        "limitations": [
            "CICIDS2017 is a benchmark dataset; this demo replays recorded flows, not live traffic.",
            "Friday attack families (DDoS, PortScan, Bot) were absent from training; the Random Forest misses most PortScan and Bot flows.",
            "The Isolation Forest flag is not a confirmed attack. An OR-combination with the Random Forest was evaluated and rejected: extra false alarms far outweighed extra detections (see backend/cic_hybrid_comparison.json).",
            "No attack-family classifier exists for CICIDS2017, so attack category is 'unknown'.",
            "risk_score is a heuristic (Random Forest attack probability x 100), not a calibrated probability.",
            "The threshold was chosen on Thursday validation data, whose attack types differ from Friday.",
            "SentryNet only raises alerts for analysts; it never blocks traffic.",
        ],
    }