"""
NetDoc Collector — FastAPI application.

Uruchomienie:
    uvicorn netdoc.api.main:app --reload --port 8000

Swagger UI: http://localhost:8000/docs
Redoc:      http://localhost:8000/redoc
Metrics:    http://localhost:8000/metrics
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netdoc.config.settings import settings
from netdoc.storage.database import init_db
from netdoc.api.routes import devices, topology, events, scan, credentials, logs as logs_route, vulnerabilities, syslog as syslog_route, metrics_if as metrics_if_route, command_ref as command_ref_route
from netdoc.api import metrics

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Inicjalizuje baze danych przy starcie aplikacji."""
    init_db()
    logger.info("NetDoc API uruchomiony na %s:%d", settings.api_host, settings.api_port)
    yield


app = FastAPI(
    title="NetDoc Collector",
    description="Universal Network Discovery & Documentation System",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routery
app.include_router(devices.router)
app.include_router(topology.router)
app.include_router(events.router)
app.include_router(scan.router)
app.include_router(credentials.router)
app.include_router(metrics.router)
app.include_router(logs_route.router)
app.include_router(vulnerabilities.router)
app.include_router(syslog_route.router)
app.include_router(metrics_if_route.router)
app.include_router(metrics_if_route.alerts_router)
app.include_router(metrics_if_route.broadcast_router)
app.include_router(command_ref_route.router)


@app.get("/", tags=["health"])
def root():
    """Health check."""
    return {"status": "ok", "version": "0.1.0", "docs": "/docs"}
