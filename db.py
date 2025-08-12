from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime,
    func, Index, JSON, Text, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import OperationalError
from config import DATABASE_URL

# Engine
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()

class ApiKey(Base):
    __tablename__ = "palisade_api_keys"

    id = Column(Integer, primary_key=True, index=True)
    # Name/email of the owner — required for /admin dashboard display
    name = Column(String(128), nullable=True)  
    key_salt = Column(String(128), nullable=False)
    key_hash = Column(String(128), nullable=False, index=True)
    prefix = Column(String(32), nullable=False, default="pal_live_")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)

Index("ix_palisade_api_keys_active_hash", ApiKey.is_active, ApiKey.key_hash)

class RequestLog(Base):
    __tablename__ = "palisade_request_logs"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("palisade_api_keys.id"), index=True, nullable=True)
    endpoint = Column(String(256), index=True)
    request_size_bytes = Column(Integer)
    status_code = Column(Integer)
    duration_ms = Column(Integer)
    # Moderation result: PG uses JSON, SQLite falls back to text
    moderation_result = Column(JSON if not DATABASE_URL.startswith("sqlite") else Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

def init_db():
    try:
        Base.metadata.create_all(bind=engine)
    except OperationalError as e:
        raise
