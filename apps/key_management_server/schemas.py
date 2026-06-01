from __future__ import annotations

from pydantic import BaseModel, Field


class GenerateDekResponse(BaseModel):
    dek_plaintext_b64: str = Field(..., description="Plaintext 256-bit DEK (base64) returned to Core Application")
    dek_encrypted_b64: str = Field(..., description="DEK encrypted with tenant master key (base64)")
    key_version: int = Field(..., description="Master key version used for encrypting the DEK")


class DecryptDekRequest(BaseModel):
    dek_encrypted_b64: str
    key_version: int


class DecryptDekResponse(BaseModel):
    dek_plaintext_b64: str


class RotateMasterKeyResponse(BaseModel):
    tenant_id: str
    key_version: int

