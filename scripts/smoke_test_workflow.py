from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import httpx
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from apps.core_app.key_client import generate_dek


def _env_required(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v


def _make_jwt(*, sub: str, tenant_id: str) -> str:
    secret = _env_required("JWT_SHARED_SECRET")
    issuer = _env_required("JWT_ISSUER")
    return jwt.encode({"sub": sub, "tenant_id": tenant_id, "iss": issuer}, secret, algorithm="HS256")


def _wait_for_openapi(base_url: str, *, timeout_s: float = 20.0) -> None:
    url = f"{base_url.rstrip('/')}/openapi.json"
    deadline = time.time() + timeout_s
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code == 200:
                return
        except Exception as e:  # noqa: BLE001
            last_exc = e
        time.sleep(0.5)
    raise RuntimeError(f"Server at {base_url} did not become ready; last error: {last_exc}")


def _start_uvicorn(module_app: str, *, host: str, port: int) -> subprocess.Popen[str]:
    # Start without reload for deterministic smoke testing.
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        module_app,
        "--host",
        host,
        "--port",
        str(port),
        "--log-level",
        "warning",
        "--workers",
        "1",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def main() -> None:
    tenant_id = os.getenv("SMOKE_TENANT_ID", "tenant_101")
    clinician_sub = os.getenv("SMOKE_CLINICIAN_SUB", "clinician_uuid_456")

    # Ensure required env vars for runtime configuration.
    _env_required("JWT_SHARED_SECRET")
    _env_required("JWT_ISSUER")
    _env_required("KEY_SERVER_DB_DSN")
    _env_required("KEY_SERVER_BASE_URL")
    _env_required("POSTGRES_HOST")
    _env_required("POSTGRES_USER")
    _env_required("POSTGRES_PASSWORD")

    host = os.getenv("SMOKE_HOST", "127.0.0.1")
    key_port = int(os.getenv("KEY_SERVER_PORT", "8001"))
    core_port = int(os.getenv("CORE_PORT", "8000"))

    key_base_url = f"http://{host}:{key_port}"
    core_base_url = f"http://{host}:{core_port}"
    token = _make_jwt(sub=clinician_sub, tenant_id=tenant_id)
    auth_header = {"Authorization": f"Bearer {token}"}

    print("smoke_test_workflow: starting servers...")
    key_proc = _start_uvicorn("apps.key_management_server.main:app", host=host, port=key_port)
    core_proc = _start_uvicorn("apps.core_app.main:app", host=host, port=core_port)
    try:
        _wait_for_openapi(key_base_url, timeout_s=60.0)
        _wait_for_openapi(core_base_url, timeout_s=60.0)

        async def run_steps() -> None:
            # Provision tenant DB (admin use case).
            async with httpx.AsyncClient(timeout=20.0) as client:
                prov_url = f"{core_base_url}/v1/admin/tenants/{tenant_id}/provision"
                r = await client.post(prov_url, headers=auth_header)
                r.raise_for_status()

                # Rotate tenant master key (so DEK generation works).
                rot_url = f"{key_base_url}/v1/tenants/{tenant_id}/master-keys/rotate"
                r = await client.post(rot_url, headers=auth_header)
                r.raise_for_status()

                # Create encrypted record using envelope encryption.
                plaintext = "Example EMR payload for tenant isolation testing"

                dek = await generate_dek(tenant_id=tenant_id, authorization_header=f"Bearer {token}")
                dek_bytes = bytes.fromhex(dek["dek_hex"])
                encrypted_dek_hex = dek["encrypted_dek_hex"]
                key_version = dek["key_version"]

                aesgcm = AESGCM(dek_bytes)
                iv = os.urandom(12)
                ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
                ciphertext = ciphertext_with_tag[:-16]
                tag = ciphertext_with_tag[-16:]

                create_url = f"{core_base_url}/v1/tenants/{tenant_id}/records"
                r = await client.post(
                    create_url,
                    headers=auth_header,
                    json={
                        "encrypted_dek_hex": encrypted_dek_hex,
                        "ciphertext_hex": ciphertext.hex(),
                        "iv_hex": iv.hex(),
                        "tag_hex": tag.hex(),
                        "payload_meta": None,
                    },
                )
                r.raise_for_status()
                record_id = r.json()["record_id"]

                # Retrieve & decrypt record.
                get_url = f"{core_base_url}/v1/tenants/{tenant_id}/records/{record_id}"
                r = await client.get(get_url, headers=auth_header)
                r.raise_for_status()
                body: dict[str, Any] = r.json()

                # Decrypt tenant DEK via key-management server.
                resp = await client.post(
                    f"{os.getenv('KEY_SERVER_BASE_URL').rstrip('/')}/v1/tenants/{tenant_id}/dek/decrypt",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"encrypted_dek_hex": body["encrypted_dek_hex"], "key_version": key_version},
                )
                resp.raise_for_status()
                dek_plain = bytes.fromhex(resp.json()["dek_hex"])

                aesgcm2 = AESGCM(dek_plain)
                ct = bytes.fromhex(body["ciphertext_hex"]) + bytes.fromhex(body["tag_hex"])
                decrypted = aesgcm2.decrypt(bytes.fromhex(body["iv_hex"]), ct, None).decode("utf-8")
                assert decrypted == plaintext, "Decrypted plaintext mismatch"

                # Tenant isolation check: token tenant_id mismatch should be rejected.
                wrong_tenant = os.getenv("SMOKE_WRONG_TENANT_ID", "tenant_999")
                wrong_token = _make_jwt(sub=clinician_sub, tenant_id=wrong_tenant)
                wrong_auth = {"Authorization": f"Bearer {wrong_token}"}

                # Send a syntactically valid encrypted record payload so auth/tenant checks can run.
                wrong_dek = await generate_dek(
                    tenant_id=wrong_tenant,
                    authorization_header=f"Bearer {wrong_token}",
                )
                wrong_dek_bytes = bytes.fromhex(wrong_dek["dek_hex"])
                wrong_encrypted_dek_hex = wrong_dek["encrypted_dek_hex"]
                wrong_key_version = wrong_dek["key_version"]

                wrong_aesgcm = AESGCM(wrong_dek_bytes)
                wrong_iv = os.urandom(12)
                wrong_ciphertext_with_tag = wrong_aesgcm.encrypt(
                    wrong_iv, b"x", None
                )
                wrong_ciphertext = wrong_ciphertext_with_tag[:-16]
                wrong_tag = wrong_ciphertext_with_tag[-16:]

                r = await client.post(
                    create_url,
                    headers=wrong_auth,
                    json={
                        "encrypted_dek_hex": wrong_encrypted_dek_hex,
                        "ciphertext_hex": wrong_ciphertext.hex(),
                        "iv_hex": wrong_iv.hex(),
                        "tag_hex": wrong_tag.hex(),
                        "payload_meta": None,
                    },
                )
                assert r.status_code == 403, "Expected 403 on tenant_id mismatch"

        import asyncio

        asyncio.run(run_steps())
        print("smoke_test_workflow: PASS")
    except Exception:
        # Best-effort: emit captured logs to speed up debugging.
        try:
            key_proc.terminate()
            core_proc.terminate()
            out_key, _ = key_proc.communicate(timeout=5)
            out_core, _ = core_proc.communicate(timeout=5)
            out = (out_key or "") + "\n" + (out_core or "")
            if out.strip():
                print("=== uvicorn combined output (truncated) ===")
                print(out[-4000:])
        except Exception:
            pass
        raise
    finally:
        key_proc.terminate()
        core_proc.terminate()


if __name__ == "__main__":
    main()

