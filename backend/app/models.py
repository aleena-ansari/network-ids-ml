from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime, timezone
from .database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)   # null if not on local network
    label = Column(String)                         # "normal" or "attack"
    category = Column(String)                      # "dos", "probe", "r2l", "u2r", "normal"
    risk_score = Column(Float)
    status = Column(String, default="new")         # new / reviewed / false_positive / escalated
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))