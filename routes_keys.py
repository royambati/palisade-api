from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional, List
from config import SIGNUP_SECRET, KEY_PREFIX, KEY_BYTES
from db import SessionLocal, ApiKey, init_db
from key_utils import generate_key, hash_key
import hashlib as _hl
from fastapi import APIRouter as _AR
from config import SIGNUP_SECRET as _SS

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

def require_signup_secret(x_signup_secret: Optional[str] = Header(default=None)):
    # In prod, require header to match SIGNUP_SECRET; in dev (unset), allow.
    if SIGNUP_SECRET:
        if not x_signup_secret or x_signup_secret != SIGNUP_SECRET:
            raise HTTPException(status_code=401, detail="Missing or invalid signup secret")

def get_api_key_record(x_api_key: Optional[str] = Header(default=None), db: Session = Depends(get_db)) -> ApiKey:
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

debug_router = _AR()

@debug_router.get("/_debug/signups")
def debug_signups():
    val = _SS or ""
    return {
        "signup_secret_present": bool(val),
        "signup_secret_len": len(val),
        "signup_secret_sha256_prefix": _hl.sha256(val.encode()).hexdigest()[:12] if val else None
    }
