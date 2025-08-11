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
# Add a sane timeout so requests don't hang forever
client = openai.OpenAI(api_key=OPENAI_API_KEY, timeout=15.0)

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

# ==== Per-key token bucket (RPM + short burst) ====
RATE_LIMIT_RPM = max(1, int(RATE_LIMIT_RPM))
RATE_LIMIT_BURST = max(1, int(max(1, RATE_LIMIT_RPM // 2)))  # allow short bursts

_buckets: Dict[str, Any] = {}
def rate_limit(request: Request, api_key: str = Depends(get_api_key)):
    now = time.time()
    window_seconds = 60.0
    capacity = RATE_LIMIT_BURST
    refill_per_sec = RATE_LIMIT_RPM / window_seconds  # tokens/sec

    tokens, last = _buckets.get(api_key, (capacity, now))
    tokens = min(capacity, tokens + (now - last) * refill_per_sec)
    if tokens < 1.0:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _buckets[api_key] = (tokens - 1.0, now)
    return api_key

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
def _extract_json(text: str) -> Dict[str, Any]:
    """Pull the first JSON object from a model response. Falls back to {}."""
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r'\{(?:[^{}]|(?R))*\}', text, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return {}
    return {}

def _as_dict(x) -> Dict[str, Any]:
    """Coerce SDK objects (e.g., pydantic models) to dicts safely."""
    if x is None:
        return {}
    if isinstance(x, dict):
        return x
    if hasattr(x, "model_dump") and callable(x.model_dump):
        return x.model_dump()
    if hasattr(x, "to_dict") and callable(x.to_dict):
        return x.to_dict()
    try:
        return {
            k: getattr(x, k)
            for k in dir(x)
            if not k.startswith("_") and not callable(getattr(x, k, None))
        }
    except Exception:
        return {}

def _log_usage(
    api_key_id: Optional[int],
    endpoint: str,
    size_bytes: int,
    status_code: int,
    duration_ms: int,
    details: Dict[str, Any]
) -> None:
    """Best-effort logging to DB; never throws."""
    try:
        db = SessionLocal()
        try:
            payload_json = json.dumps(details, separators=(",", ":"), ensure_ascii=False)
            log = RequestLog(
                api_key_id=api_key_id,
                endpoint=endpoint,
                size_bytes=size_bytes,
                status_code=status_code,
                duration_ms=duration_ms,
                payload_json=payload_json,  # adjust if your column name differs
            )
            db.add(log)
            db.commit()
        finally:
            db.close()
    except Exception:
        pass
    print(f"[LOG] api_key_id={api_key_id} endpoint={endpoint} status={status_code} size={size_bytes} duration_ms={duration_ms}")

# ---- OpenAI error mapping → consistent HTTP codes ----
def _map_openai_error(e: Exception) -> HTTPException:
    try:
        from openai import (
            APIConnectionError, APIError, RateLimitError,
            BadRequestError, AuthenticationError, PermissionDeniedError
        )
        if isinstance(e, BadRequestError):
            return HTTPException(400, f"Bad request to model: {e}")
        if isinstance(e, AuthenticationError):
            return HTTPException(401, "Upstream auth failed")
        if isinstance(e, PermissionDeniedError):
            return HTTPException(403, "Upstream permission denied")
        if isinstance(e, RateLimitError):
            return HTTPException(429, "Upstream rate limited")
        if isinstance(e, APIConnectionError):
            return HTTPException(504, "Upstream connection error")
        if isinstance(e, APIError):
            return HTTPException(502, "Upstream model error")
    except Exception:
        # If import/classes differ, fall through to generic 500 below
        pass
    return HTTPException(500, "Unexpected moderation error")

# ==== ROUTES: TEXT ====
@router.post("/moderate/text", response_model=TextModerationResponse)
async def moderate_text(request: Request, input: TextInput, api_key: str = Depends(rate_limit)):
    t0 = time.time()
    endpoint = "/moderate/text"
    try:
        # Input validation
        if not input.text or not input.text.strip():
            raise HTTPException(400, "text is required")

        resp = client.moderations.create(
            model="omni-moderation-latest",
            input=input.text
        )
        r = resp.results[0]
        flagged = bool(getattr(r, "flagged", False))

        # Coerce SDK objects to dicts safely
        categories_dict = _as_dict(getattr(r, "categories", None))
        cats = [k for k, v in categories_dict.items() if bool(v)]

        scores_dict = _as_dict(getattr(r, "category_scores", None))
        numeric_scores: List[float] = []
        for v in scores_dict.values():
            try:
                numeric_scores.append(float(v))
            except Exception:
                pass
        confidence = float(max(numeric_scores)) if numeric_scores else (1.0 if flagged else 0.0)

        suggested_action = "allow"
        if flagged:
            suggested_action = "block" if confidence >= 0.9 else "escalate"

        duration_ms = int((time.time() - t0) * 1000)
        size_est = len((input.text or "").encode("utf-8"))
        _log_usage(
            getattr(request.state, "api_key_id", None),
            endpoint,
            size_est,
            200,
            duration_ms,
            {
                "input": {"text_preview": (input.text[:2000] if input.text else "")},
                "response": {
                    "safe": not flagged,
                    "categories": cats,
                    "confidence": confidence,
                    "suggested_action": suggested_action,
                },
            },
        )

        return {
            "safe": not flagged,
            "categories": cats,
            "confidence": confidence,
            "suggested_action": suggested_action,
        }

    except HTTPException:
        # Already mapped; still log below in middleware
        raise
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        size_est = len((input.text or "").encode("utf-8")) if input and input.text else 0
        _log_usage(
            getattr(request.state, "api_key_id", None),
            endpoint,
            size_est,
            500,
            duration_ms,
            {"error": str(e)},
        )
        raise _map_openai_error(e)

# ==== ROUTES: IMAGE ====
@router.post("/moderate/image", response_model=ImageModerationResponse)
async def moderate_image(request: Request, input: ImageInput, api_key: str = Depends(rate_limit)):
    t0 = time.time()
    endpoint = "/moderate/image"
    try:
        # Input validation
        if not input.image_url or not input.image_url.strip():
            raise HTTPException(400, "image_url is required")
        if not re.match(r"^https?://", input.image_url.strip(), flags=re.I):
            raise HTTPException(400, "image_url must be http(s)")

        system_prompt = (
            "You are a content moderation system. Analyze the image and return ONLY a JSON object with:\n"
            "{"
            "\"safe\": true/false, "
            "\"categories\": [\"string\"], "
            "\"confidence\": 0.0-1.0, "
            "\"suggested_action\": \"allow/escalate/block\""
            "}\n"
            "No extra text."
        )

        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Moderate this image:"},
                        {"type": "image_url", "image_url": {"url": input.image_url}},
                    ],
                },
            ],
            max_tokens=200,
        )
        result_text = resp.choices[0].message.content
        parsed = _extract_json(result_text) or {}

        safe = bool(parsed.get("safe", True))
        categories = parsed.get("categories", [])
        try:
            confidence = float(parsed.get("confidence", 0.0))
        except Exception:
            confidence = 0.0
        suggested_action = parsed.get("suggested_action", "allow")

        duration_ms = int((time.time() - t0) * 1000)
        size_est = len((input.image_url or "").encode("utf-8"))
        _log_usage(
            getattr(request.state, "api_key_id", None),
            endpoint,
            size_est,
            200,
            duration_ms,
            {
                "input": {"image_url": input.image_url},
                "response": {
                    "safe": safe,
                    "categories": categories,
                    "confidence": confidence,
                    "suggested_action": suggested_action,
                },
            },
        )

        return {
            "safe": safe,
            "categories": categories,
            "confidence": confidence,
            "suggested_action": suggested_action,
        }

    except HTTPException:
        raise
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        size_est = len((input.image_url or "").encode("utf-8")) if input and input.image_url else 0
        _log_usage(
            getattr(request.state, "api_key_id", None),
            endpoint,
            size_est,
            500,
            duration_ms,
            {"error": str(e)},
        )
        raise _map_openai_error(e)

# ==== ROUTES: CONTEXTUAL ====
@router.post("/moderate/contextual", response_model=ContextualModerationResponse)
async def moderate_contextual(request: Request, input: ContextualInput, api_key: str = Depends(rate_limit)):
    t0 = time.time()
    endpoint = "/moderate/contextual"
    try:
        # Input validation
        if not input.conversation_id or not input.conversation_id.strip():
            raise HTTPException(400, "conversation_id is required")
        if not input.messages or not isinstance(input.messages, list):
            raise HTTPException(400, "messages[] is required")
        if not any((m.content or "").strip() for m in input.messages):
            raise HTTPException(400, "at least one message with content is required")

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
        parsed = _extract_json(result_text) or {}

        duration_ms = int((time.time() - t0) * 1000)
        size_est = sum(len((m.content or "").encode("utf-8")) for m in input.messages)

        _log_usage(
            getattr(request.state, "api_key_id", None),
            endpoint,
            size_est,
            200,
            duration_ms,
            {
                "input": {
                    "conversation_id": input.conversation_id,
                    "messages": [{"sender_id": m.sender_id, "content": m.content} for m in input.messages][:50],
                },
                "response": {
                    "safe": bool(parsed.get("safe", True)),
                    "risk_factors": parsed.get("risk_factors", []),
                    "suggested_action": parsed.get("suggested_action", "allow"),
                },
            },
        )

        return {
            "safe": bool(parsed.get("safe", True)),
            "risk_factors": parsed.get("risk_factors", []),
            "suggested_action": parsed.get("suggested_action", "allow"),
        }

    except HTTPException:
        raise
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        size_est = sum(len((m.content or "").encode("utf-8")) for m in input.messages) if input and input.messages else 0
        _log_usage(
            getattr(request.state, "api_key_id", None),
            endpoint,
            size_est,
            500,
            duration_ms,
            {"error": str(e)},
        )
        raise _map_openai_error(e)
