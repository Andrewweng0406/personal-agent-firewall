from __future__ import annotations

import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def install_api_auth(app: FastAPI, token: str | None) -> None:
    """Protect API routes when a local API token has been configured."""
    if not token:
        return

    @app.middleware("http")
    async def require_api_token(request: Request, call_next):
        if request.url.path.startswith("/api/") and request.url.path != "/api/health":
            supplied = extract_request_token(request)
            if supplied is None or not secrets.compare_digest(supplied, token):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing or invalid Agent Firewall API token"},
                )
        return await call_next(request)


def extract_request_token(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    scheme, _, credential = authorization.partition(" ")
    if scheme.lower() == "bearer" and credential:
        return credential
    return request.headers.get("x-agent-firewall-token")


def websocket_token_is_valid(supplied: str | None, expected: str | None) -> bool:
    return not expected or (
        supplied is not None and secrets.compare_digest(supplied, expected)
    )
