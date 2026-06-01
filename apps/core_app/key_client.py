from __future__ import annotations

import os
from typing import Any

import httpx


def _key_server_base_url() -> str:
    base = os.getenv("KEY_SERVER_BASE_URL")
    if not base:
        raise RuntimeError("KEY_SERVER_BASE_URL env var must be set (e.g. http://localhost:8001)")
    return base.rstrip("/")


async def generate_dek(
    *,
    tenant_id: str,
    authorization_header: str,
) -> dict[str, Any]:
    url = f"{_key_server_base_url()}/v1/tenants/{tenant_id}/dek/generate"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, headers={"Authorization": authorization_header})
        resp.raise_for_status()
        return resp.json()


async def decrypt_dek(
    *,
    tenant_id: str,
    authorization_header: str,
    dek_encrypted_b64: str,
    key_version: int,
) -> dict[str, Any]:
    url = f"{_key_server_base_url()}/v1/tenants/{tenant_id}/dek/decrypt"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            url,
            headers={"Authorization": authorization_header},
            json={"dek_encrypted_b64": dek_encrypted_b64, "key_version": key_version},
        )
        resp.raise_for_status()
        return resp.json()

