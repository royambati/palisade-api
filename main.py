from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.concurrency import iterate_in_threadpool
import logging, json, uuid, time, pathlib
from fastapi.middleware.cors import CORSMiddleware


from config import LOG_LEVEL
from routes import router
from routes_keys import router as keys_router

# Configure logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger("palisade")

app = FastAPI(
    title="Palisade Moderation API",
    description="Real-time, contextual moderation for text and image content. Built for speed, accuracy, and developer ease.",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for now, allow all
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Middleware for request ID + structured logging =====
class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        req_id = request.headers.get("x-request-id") or str(uuid.uuid4())

        # Read and stash body for downstream
        try:
            body_bytes = await request.body()
            async def receive():
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            request._receive = receive  # type: ignore
            body_preview = body_bytes[:2000].decode("utf-8", errors="ignore") if body_bytes else ""
        except Exception:
            body_preview = ""

        logger.info(json.dumps({
            "event": "request",
            "request_id": req_id,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query),
            "client": request.client.host if request.client else None,
            "has_api_key": "x-api-key" in request.headers,
            "body_preview": body_preview
        }))

        try:
            response = await call_next(request)

            # Capture response body for logging
            resp_body = b""
            async for chunk in response.body_iterator:
                resp_body += chunk
            response.body_iterator = iterate_in_threadpool(iter([resp_body]))

            duration_ms = int((time.time() - start_time) * 1000)
            logger.info(json.dumps({
                "event": "response",
                "request_id": req_id,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "response_preview": resp_body[:1000].decode("utf-8", errors="ignore")
            }))

            response.headers["x-request-id"] = req_id
            return response
        except Exception:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.exception("Unhandled error")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal Server Error", "request_id": req_id, "duration_ms": duration_ms},
                headers={"x-request-id": req_id}
            )

app.add_middleware(LoggingMiddleware)

# Mount routers
app.include_router(router)
app.include_router(keys_router)

@app.get("/", tags=["Health"])
def health():
    return {"status": "ok"}

@app.get("/test", response_class=HTMLResponse)
async def test_page():
    p = pathlib.Path("test.html")
    if p.exists():
        return HTMLResponse(p.read_text(encoding="utf-8"))
    return HTMLResponse("<h3>Missing test.html</h3>")

from fastapi.responses import HTMLResponse as _HTMLResponse
import pathlib as _pl

@app.get("/admin", response_class=_HTMLResponse)
async def admin_page():
    p = _pl.Path("admin.html")
    if p.exists():
        return _HTMLResponse(p.read_text(encoding="utf-8"))
    return _HTMLResponse("<h3>Missing admin.html</h3>")
