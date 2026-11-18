from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Always keep the database inside backend/, whatever folder uvicorn is started from.
BACKEND_DIR = Path(__file__).resolve().parents[1]
DATABASE_URL = f"sqlite:///{(BACKEND_DIR / 'alerts.db').as_posix()}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()