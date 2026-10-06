"""Rakshak-AI FastAPI application entrypoint.

Synthetic cyber-range demonstrator. Defensive only. No real intrusion,
exploitation, scanning or response actions are performed anywhere.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db
from .routes import (
    actions,
    analysis,
    blast_radius,
    graph,
    health,
    incidents,
    metrics,
    scenarios,
    telemetry,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Synthetic, defensive cyber-range SOC prototype (OCSF-compatible, not certified).",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in (health, telemetry, scenarios, incidents, blast_radius, graph, metrics, analysis, actions):
    app.include_router(module.router)


@app.get("/")
def root() -> dict:
    return {
        "name": settings.app_name,
        "safety": "SIMULATION ONLY - synthetic cyber-range. Defensive prototype, not production-certified.",
        "docs": "/docs",
        "ocsf_schema_version": settings.ocsf_schema_version,
    }
