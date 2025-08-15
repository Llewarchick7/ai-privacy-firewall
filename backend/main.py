"""
Main entry point for the ai-privacy-firewall API.
Ensures authentication routes are accessible at /api/users.
"""

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import time
from backend.routes import users, privacy, dns
from backend.services.stream import stream_manager
from backend.services.auth import decode_access_token
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from backend.database import Base, engine, get_db
# Import model modules before creating tables so relationships resolve
from backend.models import users as users_model  
from backend.models import dns_models as dns_models_model  
from backend.models import audit_log as audit_log_model  
from sqlalchemy.orm import Session

# Initialize database (after models are imported)
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="AI Privacy Firewall API",
    description="AI-powered DNS firewall for network threat detection and privacy protection",
    version="1.0.0"
)

# Optional debug logging middleware (enable with DEBUG_LOG_REQUESTS=1)
if os.getenv("DEBUG_LOG_REQUESTS", "0") == "1":
    from starlette.middleware.base import BaseHTTPMiddleware
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("reqlog")

    class RequestLogMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            start = time.time()
            try:
                body_bytes = await request.body()
            except Exception:
                body_bytes = b''
            logger.info("➡ %s %s origin=%s len=%d", request.method, request.url.path, request.headers.get('origin'), len(body_bytes))
            response = await call_next(request)
            dur = (time.time() - start) * 1000
            logger.info("⬅ %s %s %d %.1fms", request.method, request.url.path, response.status_code, dur)
            return response
    app.add_middleware(RequestLogMiddleware)

"""CORS (Cross-Origin Resource Sharing)
Dev note: Browsers reject wildcard origins when Access-Control-Allow-Credentials is true.
If we allow all origins for quick local testing we disable credentials (we're not using cookies anyway).
In stricter mode we enumerate allowed origins and allow credentials.
"""
if os.getenv("DEV_ALLOW_ALL_ORIGINS", "1") == "1":
    cors_allow_origins = ["*"]
    cors_allow_credentials = False  # must be False with wildcard for browser compliance
else:
    cors_allow_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        os.getenv("FRONTEND_URL", "http://localhost:3000"),
    ]
    cors_allow_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allow_origins,
    allow_credentials=cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Global exception logging to surface stack traces during "Failed to fetch" browser errors
if os.getenv("DEBUG_LOG_EXCEPTIONS", "1") == "1":
    import logging, traceback
    logger = logging.getLogger("apiexceptions")
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO)

    @app.middleware("http")
    async def log_exceptions(request, call_next):  # type: ignore
        try:
            return await call_next(request)
        except Exception as exc:  # pragma: no cover (debug path)
            tb = traceback.format_exc()
            logger.error("Unhandled exception %s %s\n%s", request.method, request.url.path, tb)
            return JSONResponse({"detail": "Internal Server Error", "error": str(exc)}, status_code=500)

# Include routers
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(privacy.router, prefix="/api/privacy", tags=["Privacy"])
app.include_router(dns.router, prefix="/api/dns", tags=["DNS Monitoring"])

@app.get("/")
def read_root(db: Session = Depends(get_db)):
    return {"message": "Database connection successful"}

@app.get("/api/health")
def health_check():
    """Health check endpoint for monitoring and testing"""
    return {
        "status": "healthy",
        "service": "AI Privacy Firewall API",
        "version": "1.0.0"
    }

# Metrics
dns_queries_streamed = Counter('dns_queries_streamed_total', 'Total DNS query events streamed to clients')
stream_clients_connected = Counter('stream_clients_total', 'Total WebSocket clients ever connected')

@app.get('/metrics')
def metrics():
    return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

@app.websocket('/api/dns/stream')
async def dns_stream(ws: WebSocket):
    # Expect token query param ?token= or Authorization header (not exposed in plain WS easily) so use query
    token = ws.query_params.get('token')
    if not token:
        await ws.close(code=4401)
        return
    payload = decode_access_token(token)
    if not payload or 'sub' not in payload:
        await ws.close(code=4401)
        return
    await ws.accept()
    stream_clients_connected.inc()
    queue = await stream_manager.connect()
    try:
        while True:
            item = await queue.get()
            dns_queries_streamed.inc()
            await ws.send_json(item)
    except WebSocketDisconnect:
        pass
    finally:
        await stream_manager.disconnect(queue)


   
