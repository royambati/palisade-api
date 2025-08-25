# routes_admin.py
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_
from typing import Optional, List, Dict, Any
from db import SessionLocal, ApiKey, RequestLog
from config import ADMIN_TOKEN
import datetime as dt
import uuid

router = APIRouter(prefix="/admin", tags=["admin"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def require_admin(request: Request):
    token = request.headers.get("X-Admin-Token")
    if not token or token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

@router.get("/users")
def list_users(q: Optional[str] = None, db: Session = Depends(get_db), _: None = Depends(require_admin)):
    # group by email from ApiKey
    query = db.query(ApiKey.email, func.count(ApiKey.id).label("key_count"), func.min(ApiKey.created_at).label("created_at"))\
              .group_by(ApiKey.email)
    if q:
        query = query.having(ApiKey.email.ilike(f"%{q}%"))
    rows = query.order_by(func.min(ApiKey.created_at).desc()).limit(200).all()
    return [{"email": r[0], "key_count": r[1], "created_at": r[2].isoformat() if r[2] else None} for r in rows]

@router.get("/keys")
def list_keys(email: str = Query(...), db: Session = Depends(get_db), _: None = Depends(require_admin)):
    keys = db.query(ApiKey).filter(ApiKey.email == email).order_by(ApiKey.created_at.desc()).limit(100).all()
    return [{
        "key": k.key,
        "email": k.email,
        "active": bool(getattr(k, "active", True)),
        "created_at": k.created_at.isoformat() if k.created_at else None
    } for k in keys]

@router.post("/keys")
def create_key(payload: Dict[str, Any], db: Session = Depends(get_db), _: None = Depends(require_admin)):
    email = (payload.get("email") or "").strip()
    if not email:
        raise HTTPException(400, "email required")
    new_key = ApiKey(key=str(uuid.uuid4()), email=email, active=True)
    db.add(new_key); db.commit(); db.refresh(new_key)
    return {"ok": True, "key": new_key.key}

@router.get("/logs")
def list_logs(
    email: Optional[str] = None,
    q: Optional[str] = None,
    from_: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = None,
    limit: int = 25,
    cursor: Optional[int] = None,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    limit = max(1, min(limit, 200))

    # Basic cursor = last seen id (descending id order)
    base = db.query(RequestLog).order_by(RequestLog.id.desc())
    if cursor:
        base = base.filter(RequestLog.id < cursor)

    if email:
        base = base.filter(RequestLog.user_email == email)

    if q:
        like = f"%{q}%"
        base = base.filter(or_(
            RequestLog.request_body.ilike(like),
            RequestLog.response_body.ilike(like),
            RequestLog.path.ilike(like)
        ))

    def parse_ts(s):
        try:
            return dt.datetime.fromisoformat(s.replace("Z",""))
        except Exception:
            return None

    f_dt = parse_ts(from_) if from_ else None
    t_dt = parse_ts(to) if to else None
    if f_dt:
        base = base.filter(RequestLog.created_at >= f_dt)
    if t_dt:
        base = base.filter(RequestLog.created_at <= t_dt)

    items = base.limit(limit + 1).all()
    next_cursor = items[-1].id if len(items) > limit else None
    items = items[:limit]

    def preview(s: Optional[str], n=140):
        if not s:
            return None
        return s[:n]

    out = []
    for r in items:
        out.append({
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "email": getattr(r, "user_email", None),
            "path": r.path,
            "status_code": r.status_code,
            "request_preview": preview(r.request_body),
            "response_preview": preview(r.response_body),
            "request_body": r.request_body,
            "response_body": r.response_body,
            "duration_ms": r.duration_ms,
            "method": r.method,
            "request_id": r.request_id,
        })
    return {"items": out, "next_cursor": next_cursor}
