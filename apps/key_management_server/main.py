import os
import hashlib
from typing import Dict

from fastapi import FastAPI
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel

from apps.shared.secure_logging import get_audit_logger

app = FastAPI(title="Key Management Server")
logger = get_audit_logger("kms", log_file="logs/kms_audit.enc.log")

_master_key_store: Dict[str, Dict] = {}

class DEKResponse(BaseModel):
    dek_hex: str
    encrypted_dek_hex: str
    key_version: int

def _get_tenant_key(tenant_id: str):
    if tenant_id not in _master_key_store:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        public_key = private_key.public_key()
        _master_key_store[tenant_id] = {
            "private_key_pem": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "public_key_pem": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "version": 1,
        }
    return _master_key_store[tenant_id]

def generate_data_encryption_key() -> bytes:
    """Generate a 256-bit AES Data Encryption Key."""
    return AESGCM.generate_key(bit_length=256)

def _key_fp(key_bytes: bytes) -> str:
    """Return a non-revealing fingerprint for correlation."""
    return hashlib.sha256(key_bytes).hexdigest()[:16]

@app.post("/v1/tenants/{tenant_id}/master-keys/rotate")
async def rotate_master_key(tenant_id: str):
    old_entry = _master_key_store.pop(tenant_id, None)
    new_entry = _get_tenant_key(tenant_id)
    new_version = (old_entry["version"] + 1) if old_entry else 1
    new_entry["version"] = new_version
    _master_key_store[tenant_id] = new_entry
    logger.info("master_key_rotated", extra={"tenant_id": tenant_id, "new_version": new_version})
    return {"tenant_id": tenant_id, "new_version": new_version}

@app.post("/v1/tenants/{tenant_id}/dek/generate", response_model=DEKResponse)
async def generate_dek(tenant_id: str):
    tenant = _get_tenant_key(tenant_id)
    public_key = serialization.load_pem_public_key(tenant["public_key_pem"])
    dek = generate_data_encryption_key()
    encrypted_dek = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    dek_fingerprint = _key_fp(dek)
    logger.info(
        "dek_generated",
        extra={
            "tenant_id": tenant_id,
            "key_version": tenant["version"],
            "dek_fingerprint": dek_fingerprint,
        }
    )
    return DEKResponse(
        dek_hex=dek.hex(),
        encrypted_dek_hex=encrypted_dek.hex(),
        key_version=tenant["version"],
    )

@app.post("/v1/tenants/{tenant_id}/dek/decrypt")
async def decrypt_dek(tenant_id: str, payload: Dict):
    tenant = _get_tenant_key(tenant_id)
    private_key = serialization.load_pem_private_key(tenant["private_key_pem"], password=None)
    encrypted_dek = bytes.fromhex(payload.get("encrypted_dek_hex", ""))
    dek = private_key.decrypt(
        encrypted_dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    dek_fingerprint = _key_fp(dek)
    logger.info(
        "dek_decrypted",
        extra={
            "tenant_id": tenant_id,
            "key_version": tenant["version"],
            "dek_fingerprint": dek_fingerprint,
        }
    )
    return {"dek_hex": dek.hex()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
