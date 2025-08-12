from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.concurrency import iterate_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
import logging, json, uuid, time, pathlib

from config import LOG_LEVEL, ADMIN_TOKEN
from db import init_db, SessionLocal, RequestLog, ApiKey
from routes import router
from routes_keys import router as keys_router

# Configure logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger("palisade")

app = FastAPI(
    title="Palisade Moderation API",
    description="Real-time, contextual moderation for text and image content. Built for speed, accuracy, and developer ease.",
    version="1.2.0",
)

# CORS (keep permissive for now; tighten later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Startup: init DB once + list routes =====
@app.on_event("startup")
async def on_startup():
    try:
        logger.info("Initializing database...")
        init_db()
        logger.info("DB initialized.")
    except Exception:
        logger.exception("DB init failed (continuing; routes may still work).")

    # Print mounted routes for quick sanity check
    try:
        logger.info("=== ROUTES ===")
        for r in app.router.routes:
            if isinstance(r, APIRoute):
                logger.info(f"{','.join(sorted(r.methods)):<10} {r.path}")
    except Exception:
        logger.exception("Failed to print routes")

# ===== Middleware for request ID + structured logging =====
class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = req_id  # make available downstream

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

# ===== Mount routers =====
app.include_router(router)        # /moderate/*
app.include_router(keys_router)   # /keys/* (create/revoke/etc.)

# ===== Admin logs API =====
def verify_admin(request: Request):
    token = request.query_params.get("admin_token")
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")

@app.get("/admin/logs")
def get_logs(_: str = Depends(verify_admin)):
    db = SessionLocal()
    try:
        rows = (
            db.query(RequestLog, ApiKey.email)
            .join(ApiKey, RequestLog.api_key_id == ApiKey.id, isouter=True)
            .order_by(RequestLog.created_at.desc())
            .limit(500)
            .all()
        )
        return [
            {
                "email": email or "(no email)",
                "endpoint": r.endpoint,
                "status_code": r.status_code,
                "duration_ms": r.duration_ms,
                "payload": json.loads(r.payload_json or "{}"),
                "created_at": r.created_at.isoformat() if hasattr(r, "created_at") and r.created_at else None
            }
            for r, email in rows
        ]
    finally:
        db.close()

# ===== Health & admin dashboard =====
@app.get("/", tags=["Health"])
def health():
    return {"status": "ok"}

@app.get("/admin/data", response_class=JSONResponse)
async def admin_data():
    """
    Returns the latest request logs for the admin dashboard.
    """
    db: Session = SessionLocal()
    try:
        stmt = (
            select(
                RequestLog.created_at,
                ApiKey.name.label("user_email"),
                RequestLog.endpoint,
                RequestLog.moderation_result,
                RequestLog.duration_ms,
                RequestLog.status_code
            )
            .outerjoin(ApiKey, RequestLog.api_key_id == ApiKey.id)
            .order_by(RequestLog.created_at.desc())
            .limit(100)
        )
        rows = db.execute(stmt).all()

        results = []
        for r in rows:
            try:
                moderation_result = (
                    r.moderation_result
                    if isinstance(r.moderation_result, dict)
                    else pyjson.loads(r.moderation_result or "{}")
                )
            except Exception:
                moderation_result = {}

            results.append({
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "user_email": r.user_email or "",
                "endpoint": r.endpoint,
                "request_content": moderation_result.get("input", {}),
                "response": moderation_result.get("response", {}),
                "duration_ms": r.duration_ms,
                "status_code": r.status_code,
            })

        return JSONResponse(content=results)

    finally:
        db.close()

@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Palisade Admin</title>
      <style>
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; vertical-align: top; }
        tr:nth-child(even) { background: #f9f9f9; }
        th { background: #333; color: white; position: sticky; top: 0; }
        input { margin-bottom: 10px; padding: 5px; width: 300px; }
        pre { max-width: 400px; white-space: pre-wrap; word-wrap: break-word; }
      </style>
    </head>
    <body>
      <h2>Palisade Request Logs</h2>
      <input type="text" id="filter" placeholder="Search email or endpoint...">
      <table id="logs">
        <thead>
          <tr><th>Email</th><th>Endpoint</th><th>Request</th><th>Response</th><th>Duration</th><th>Status</th></tr>
        </thead>
        <tbody></tbody>
      </table>

      <script>
        const token = prompt("Enter admin token:");
        fetch(`/admin/logs?admin_token=${token}`)
          .then(r => r.json())
          .then(data => {
            const tbody = document.querySelector("#logs tbody");
            data.forEach(row => {
              const tr = document.createElement("tr");
              tr.innerHTML = `
                <td>${row.email}</td>
                <td>${row.endpoint}</td>
                <td><pre>${JSON.stringify(row.payload.input || {}, null, 2)}</pre></td>
                <td><pre>${JSON.stringify(row.payload.response || {}, null, 2)}</pre></td>
                <td>${row.duration_ms} ms</td>
                <td>${row.status_code}</td>
              `;
              tbody.appendChild(tr);
            });
            document.getElementById("filter").addEventListener("input", function() {
              const q = this.value.toLowerCase();
              document.querySelectorAll("#logs tbody tr").forEach(tr => {
                tr.style.display = tr.innerText.toLowerCase().includes(q) ? "" : "none";
              });
            });
          });
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
