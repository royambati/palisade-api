from fastapi import APIRouter, HTTPException, Security, Depends, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional, Any, Dict
import openai
import json
import time
import re

from config import OPENAI_API_KEY, PALISADE_API_KEYS, RATE_LIMIT_RPM
from db import SessionLocal, ApiKey, RequestLog, init_db
from key_utils import hash_key

router = APIRouter()
client = openai.OpenAI(api_key=OPENAI_API_KEY)

# ==== API Key Auth ====
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

def get_api_key(request: Request, api_key: str = Security(api_key_header)) -> str:
    init_db()
    # 1) Try DB-backed keys
    if api_key:
        db = SessionLocal()
        try:
            rows = db.query(ApiKey).filter(ApiKey.is_active == True).all()
            for rec in rows:
                if hash_key(rec.key_salt, api_key) == rec.key_hash:
                    request.state.api_key_id = rec.id
                    return api_key
        finally:
            db.close()
    # 2) Fallback to env-based keys (legacy/testing)
    if not PALISADE_API_KEYS:
        request.state.api_key_id = None  # dev mode
        return "dev-mode"
    if api_key and api_key in PALISADE_API_KEYS:
        request.state.api_key_id = None
        return api_key
    raise HTTPException(status_code=401, detail="Invalid or missing API key")

# ==== Simple in-memory token bucket per key ====
_buckets: Dict[str, Any] = {}
def rate_limit(request: Request, api_key: str = Depends(get_api_key)):
    now = time.time()
    window = 60.0
    capacity = max(1, RATE_LIMIT_RPM)
    refill = capacity / window  # tokens/sec

    tokens, last = _buckets.get(api_key, (capacity, now))
    tokens = min(capacity, tokens + (now - last) * refill)
    if tokens >= 1.0:
        tokens -= 1.0
        _buckets[api_key] = (tokens, now)
        return api_key
    raise HTTPException(status_code=429, detail="Rate limit exceeded")

# ==== INPUT MODELS ====
class TextInput(BaseModel):
    text: str

class ImageInput(BaseModel):
    image_url: str

class Message(BaseModel):
    sender_id: str
    content: str
    timestamp: Optional[str] = None

class ContextualInput(BaseModel):
    conversation_id: str
    messages: List[Message]

# ==== RESPONSE MODELS ====
class TextModerationResponse(BaseModel):
    safe: bool
    categories: List[str]
    confidence: float
    suggested_action: str

class ImageModerationResponse(BaseModel):
    safe: bool
    categories: List[str]
    confidence: float
    suggested_action: str

class ContextualModerationResponse(BaseModel):
    safe: bool
    risk_factors: List[str]
    suggested_action: str

# ==== Helpers ====
def _log_usage(api_key_id, endpoint, duration_ms):
           "/moderate/contextual",
           size_est,
           200,
           duration_ms,
           {"input": {"conversation_id": input.conversation_id,
                      "messages": [{"sender_id": m.sender_id, "content": m.content} for m in input.messages][:50]},
            "response": {
                "safe": bool(parsed.get("safe", True)),
                "risk_factors": parsed.get("risk_factors", []),
                "suggested_action": parsed.get("suggested_action", "allow")
            }}
    print(f"API key {api_key_id} used {endpoint} in {duration_ms}ms")    
)
async def moderate_contextual(request: Request, input: ContextualInput, api_key: str = Depends(rate_limit)):
    t0 = time.time()
    try:
        messages_formatted = "\n".join(
            [f"{m.timestamp or ''} {m.sender_id}: {m.content}" for m in input.messages]
        )

        system_prompt = (
            "You are a trust & safety analyst. Analyze the following conversation for grooming, manipulation, "
            "harassment, power imbalance, or any kind of risk.\n\n"
            "Return only a JSON object with:\n"
            "{"
            "\"safe\": true/false, "
            "\"risk_factors\": [\"string\"], "
            "\"suggested_action\": \"allow/escalate/block\""
            "}\n\n"
            "DO NOT include any explanation. ONLY return the JSON."
        )

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": messages_formatted}
            ],
            max_tokens=400
        )

        result_text = response.choices[0].message.content
        parsed = _extract_json(result_text)

        duration_ms = int((time.time() - t0) * 1000)
        size_est = sum(len((m.content or "").encode("utf-8")) for m in input.messages)
        _log_usage(getattr(request.state, "api_key_id", None), "/moderate/contextual", size_est, 200, duration_ms, parsed)

        return {
            "safe": bool(parsed.get("safe", True)),
            "risk_factors": parsed.get("risk_factors", []),
            "suggested_action": parsed.get("suggested_action", "allow"),
        }
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        size_est = sum(len((m.content or "").encode("utf-8")) for m in input.messages)
        _log_usage(getattr(request.state, "api_key_id", None), "/moderate/contextual", size_est, 500, duration_ms, {"error": str(e)})
        raise HTTPException(status_code=500, detail=f"Contextual moderation failed: {str(e)}")
