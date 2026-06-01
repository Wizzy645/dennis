from __future__ import annotations

from pydantic import BaseModel, Field


class CreateRecordRequest(BaseModel):
    plaintext: str = Field(..., description="Plain medical record payload to be encrypted for storage")


class CreateRecordResponse(BaseModel):
    record_id: str


class GetRecordResponse(BaseModel):
    record_id: str
    plaintext: str


class ProvisionTenantResponse(BaseModel):
    tenant_id: str

