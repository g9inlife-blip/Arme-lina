"""FastAPI entrypoint (DRAFT)."""
from __future__ import annotations

from fastapi import FastAPI

from .routes import allin1, anon, login

app = FastAPI(title="Arme Local Private Server (DRAFT)")

app.include_router(allin1.router, tags=["bootstrap"])
app.include_router(anon.router, tags=["account"])
app.include_router(login.router, tags=["account"])


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "draft"}
