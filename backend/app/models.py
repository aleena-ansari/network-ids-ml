from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Float, DateTime

from .database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)      # null if not on the local network
    label = Column(String)                            # "normal" or "attack"
    category = Column(String)                         # "unknown" for attacks, "normal" otherwise
    attack_probability = Column(Float)                # Random Forest probability, 0 to 1
    risk_score = Column(Float)                        # heuristic: probability x 100
    anomaly_score = Column(Float)                     # Isolation Forest score (lower = more unusual)
    anomaly_detected = Column(Integer, default=0)     # 1 = unusual-traffic flag (NOT a confirmed attack)
    detection_source = Column(String, default="none") # random_forest / isolation_forest_flag / none
    origin = Column(String, default="api")            # "simulated" or "api"
    status = Column(String, default="new")            # new / reviewed / false_positive / escalated
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))