import os
import json
from typing import Dict, Optional

from fastapi import Depends, FastAPI, HTTPException
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel

from apps.common.jwt_auth import get_current_principal
from apps.shared.secure_logging import get_audit_logger

app = FastAPI(title="Core Medical Application API")
logger = get_audit_logger("core_app", log_file="logs/core_audit.enc.log")

_record_store: Dict[str, Dict[str, Dict]] = {}

class CreateRecordRequest(BaseModel):
    encrypted_dek_hex: str
    ciphertext_hex: str
    iv_hex: str
    tag_hex: str
    payload_meta: Optional[Dict] = None

def encrypt_record(payload_bytes: bytes, dek: bytes) -> Dict[str, str]:
    """AES-256-GCM envelope encryption of a payload."""
    aesgcm = AESGCM(dek)
    iv = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(iv, payload_bytes, None)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return {
        "ciphertext_hex": ciphertext.hex(),
        "iv_hex": iv.hex(),
        "tag_hex": tag.hex(),
    }

def decrypt_record(ciphertext_hex: str, iv_hex: str, tag_hex: str, dek: bytes) -> bytes:
    """Decrypt an AES-256-GCM envelope."""
    aesgcm = AESGCM(dek)
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)
    return aesgcm.decrypt(bytes.fromhex(iv_hex), ciphertext + tag, None)

@app.post("/v1/admin/tenants/{tenant_id}/provision")
async def provision_tenant(tenant_id: str):
    if tenant_id not in _record_store:
        _record_store[tenant_id] = {}
    logger.info("tenant_provisioned", extra={"tenant_id": tenant_id})
    return {"tenant_id": tenant_id, "status": "provisioned"}

@app.post("/v1/tenants/{tenant_id}/records")
async def create_record(
    tenant_id: str,
    req: CreateRecordRequest,
    principal=Depends(get_current_principal),
):
    if principal.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if tenant_id not in _record_store:
        raise HTTPException(status_code=404, detail="Tenant not provisioned")
    record_id = os.urandom(16).hex()
    row = req.dict()
    row["record_id"] = record_id
    _record_store[tenant_id][record_id] = row
    logger.info(
        "record_created",
        extra={
            "tenant_id": tenant_id,
            "record_id": record_id,
            "has_encrypted_dek": bool(req.encrypted_dek_hex),
        }
    )
    return {"record_id": record_id, "tenant_id": tenant_id}

@app.get("/v1/tenants/{tenant_id}/records/{record_id}")
async def get_record(
    tenant_id: str,
    record_id: str,
    principal=Depends(get_current_principal),
):
    if principal.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if tenant_id not in _record_store:
        raise HTTPException(status_code=404, detail="Tenant not found")
    record = _record_store[tenant_id].get(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    logger.info(
        "record_accessed",
        extra={
            "tenant_id": tenant_id,
            "record_id": record_id,
        }
    )
    return {
        "record_id": record["record_id"],
        "encrypted_dek_hex": record["encrypted_dek_hex"],
        "ciphertext_hex": record["ciphertext_hex"],
        "iv_hex": record["iv_hex"],
        "tag_hex": record["tag_hex"],
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
