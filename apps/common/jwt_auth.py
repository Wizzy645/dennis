from __future__ import annotations

import os
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class JwtPrincipal:
    subject: str
    tenant_id: str


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SHARED_SECRET")
    if not secret:
        raise RuntimeError("JWT_SHARED_SECRET env var must be set")
    return secret


def _jwt_issuer() -> str:
    issuer = os.getenv("JWT_ISSUER", "local-emr-auth-service")
    if not issuer:
        raise RuntimeError("JWT_ISSUER env var must be set")
    return issuer


def _decode(token: str) -> dict:
    """
    JWT validation as referenced by the document (activity diagram).

    Assumes HMAC signing using `JWT_SHARED_SECRET`.
    """
    return jwt.decode(
        token,
        _jwt_secret(),
        algorithms=["HS256"],
        issuer=_jwt_issuer(),
        options={"require": ["sub", "tenant_id"], "verify_aud": False},
    )

async def get_current_principal(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    """
    Require a valid JWT bearer token.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")

    try:
        payload = _decode(credentials.credentials)
        sub = str(payload["sub"])
        tenant_id = str(payload["tenant_id"])
        return JwtPrincipal(subject=sub, tenant_id=tenant_id)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

