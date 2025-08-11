from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, cast
from sqlalchemy.types import String
from typing import Optional, List
from config import SIGNUP_SECRET, KEY_PREFIX, KEY_BYTES
from db import SessionLocal, ApiKey, RequestLog, init_db
from key_utils import generate_key, hash_key

init_db()
router = APIRouter()

class KeyCreateRequest(BaseModel):
    name: Optional[str] = Field(None, description="Label or owner email for this key")

class KeyCreateResponse(BaseModel):
    key: str
    id: int

class KeyInfo(BaseModel):
    id: int
    name: Optional[str]
    prefix: str
    is_active: bool

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def require_signup_secret(x_signup_secret: Optional[str] = Header(default=None, convert_underscores=False)):
    # In prod, require header to match SIGNUP_SECRET; in dev (unset), allow.
    if SIGNUP_SECRET:
        if not x_signup_secret or x_signup_secret != SIGNUP_SECRET:
            raise HTTPException(status_code=401, detail="Missing or invalid signup secret")

def get_api_key_record(x_api_key: Optional[str] = Header(default=None, convert_underscores=False), db: Session = Depends(get_db)) -> ApiKey:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    rows = db.query(ApiKey).filter(ApiKey.is_active == True).all()
    for rec in rows:
        if hash_key(rec.key_salt, x_api_key) == rec.key_hash:
            return rec
    raise HTTPException(status_code=401, detail="Invalid API key")

@router.post("/keys", response_model=KeyCreateResponse, summary="Create a new API key (self-serve)")
def create_key(payload: KeyCreateRequest, db: Session = Depends(get_db), _ok=Depends(require_signup_secret)):
    plaintext, salt, h = generate_key(KEY_PREFIX, KEY_BYTES)
    rec = ApiKey(name=payload.name, key_salt=salt, key_hash=h, prefix=KEY_PREFIX, is_active=True)
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return {"key": plaintext, "id": rec.id}

@router.get("/keys/me", response_model=KeyInfo, summary="Get info about your API key")
def me(rec: ApiKey = Depends(get_api_key_record)):
    return {"id": rec.id, "name": rec.name, "prefix": rec.prefix, "is_active": rec.is_active}

@router.delete("/keys/me", summary="Revoke your API key")
def revoke_self(rec: ApiKey = Depends(get_api_key_record), db: Session = Depends(get_db)):
    rec.is_active = False
    db.add(rec)
    db.commit()
    return {"ok": True, "message": "Key revoked"}

# Admin utilities
@router.get("/admin/keys", response_model=List[KeyInfo], summary="List keys (admin)")
def admin_list(db: Session = Depends(get_db), _ok=Depends(require_signup_secret)):
    rows = db.query(ApiKey).order_by(ApiKey.id.desc()).all()
    return [KeyInfo(id=r.id, name=r.name, prefix=r.prefix, is_active=r.is_active) for r in rows]

@router.delete("/admin/keys/{key_id}", summary="Revoke key by id (admin)")
def admin_revoke(key_id: int, db: Session = Depends(get_db), _ok=Depends(require_signup_secret)):
    rec = db.query(ApiKey).get(key_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Key not found")
    rec.is_active = False
    db.add(rec)
    db.commit()
    return {"ok": True, "message": f"Key {key_id} revoked"}

# ===== Debug endpoint (no secret value leak) =====
import hashlib as _hl
from fastapi import APIRouter as _AR
from config import SIGNUP_SECRET as _SS

debug_router = _AR()

@debug_router.get("/_debug/signups")
def debug_signups():
    val = _SS or ""
    return {
        "signup_secret_present": bool(val),
        "signup_secret_len": len(val),
        "signup_secret_sha256_prefix": _hl.sha256(val.encode()).hexdigest()[:12] if val else None
    }


@router.get("/admin/logs", summary="List recent request logs (admin)")
def admin_logs(
    limit: int = 50,
    offset: int = 0,
    api_key_id: int = None,
    user_email: str = None,
    contains: str = None,
    endpoint: str = None,
    db: Session = Depends(get_db),
    _ok=Depends(require_signup_secret)
):
    q = db.query(RequestLog).order_by(desc(RequestLog.id))

    # Filter by endpoint
    if endpoint:
        q = q.filter(RequestLog.endpoint == endpoint)

    # Filter by api_key_id
    if api_key_id is not None:
        q = q.filter(RequestLog.api_key_id == api_key_id)

    # Filter by email via ApiKey.name (owner/email field)
    if user_email:
        key_ids = [r.id for r in db.query(ApiKey.id).filter(ApiKey.name.ilike(f"%{user_email}%")).all()]
        if key_ids:
            q = q.filter(RequestLog.api_key_id.in_(key_ids))
        else:
            return {"items": [], "limit": limit, "offset": offset}

    # Search 'contains' within moderation_result JSON/Text
    if contains:
        q = q.filter(cast(RequestLog.moderation_result, String).ilike(f"%{contains}%"))

    rows = q.offset(offset).limit(min(max(limit, 1), 500)).all()

    # Map api_key_id -> owner (email/name)
    key_rows = db.query(ApiKey.id, ApiKey.name).all()
    owner_map = {kid: nm for kid, nm in key_rows}

    out = []
    for r in rows:
        preview = None
        try:
            blob = r.moderation_result
            preview = blob if isinstance(blob, str) else str(blob)
            if len(preview) > 600:
                preview = preview[:600] + "...(truncated)"
        except Exception:
            preview = None
        out.append({
            "id": r.id,
            "api_key_id": r.api_key_id,
            "api_key_owner": owner_map.get(r.api_key_id),
            "endpoint": r.endpoint,
            "status_code": r.status_code,
            "duration_ms": r.duration_ms,
            "request_size_bytes": r.request_size_bytes,
            "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") and r.created_at else None,
            "moderation_result_preview": preview
        })
    return {"items": out, "limit": limit, "offset": offset}



@router.get("/admin/logs/{log_id}", summary="Get full log record (admin)")
def admin_log_detail(log_id: int, db: Session = Depends(get_db), _ok=Depends(require_signup_secret)):
    r = db.query(RequestLog).get(log_id)
    if not r:
        raise HTTPException(status_code=404, detail="Log not found")
    owner = db.query(ApiKey).get(r.api_key_id) if r.api_key_id else None
    return {
        "id": r.id,
        "api_key_id": r.api_key_id,
        "api_key_owner": getattr(owner, "name", None),
        "endpoint": r.endpoint,
        "status_code": r.status_code,
        "duration_ms": r.duration_ms,
        "request_size_bytes": r.request_size_bytes,
        "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") and r.created_at else None,
        "moderation_result": r.moderation_result,
    }

