from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import settings
from app.database.database import init_db
from app.api.routes import pcap, health, detection, features, alerts


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="DNS Tunneling Detection and Data Exfiltration Monitoring System - Rule-based detection approach",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(pcap.router, prefix="/api", tags=["pcap"])
app.include_router(detection.router, prefix="/api", tags=["detection"])
app.include_router(features.router, prefix="/api", tags=["features"])
app.include_router(alerts.router, prefix="/api", tags=["alerts"])


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "DNS Tunneling Detection System - Rule-based analysis",
        "docs": "/docs",
    }