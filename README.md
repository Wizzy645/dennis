# Secure Cryptographic Key Management System (EMR)

This workspace implements the architecture described in:
`Design and Implementation of a Secure Cryptographic Key Management System for Electronic Medical Records in Local Healthcare Providers.txt`

It includes two FastAPI services:

1. **Standalone Key Management Server** (FastAPI)
   - Generates 256-bit Data Encryption Keys (DEKs)
   - Protects DEKs using **asymmetric encryption** (RSA-OAEP)
   - Returns both the **plaintext DEK** and the **encrypted DEK** to the Core Medical Application
   - Decrypts encrypted DEKs on authorization
   - Supports per-tenant master key rotation

2. **Core Medical Application API** (FastAPI)
   - Creates and retrieves encrypted medical records
   - Encrypts payloads using **AES-256-GCM Envelope Encryption**
   - Stores: ciphertext, authentication tag, initialization vector, and encrypted DEK
   - Scrubs plaintext DEKs after AES-GCM encryption/decryption
   - Uses **database-per-tenant** logical separation in PostgreSQL

## Environment variables

See `apps/key_management_server/.env.example` and `apps/core_app/.env.example`.

## Running

From this folder:

```powershell
pip install -r requirements.txt

uvicorn apps.key_management_server.main:app --reload --port 8001
uvicorn apps.core_app.main:app --reload --port 8000
```

## Endpoints (mapped to the document workflow)

Key Management Server (port `8001`)

- `POST /v1/tenants/{tenant_id}/master-keys/rotate`
- `POST /v1/tenants/{tenant_id}/dek/generate`
- `POST /v1/tenants/{tenant_id}/dek/decrypt`

Core Medical Application API (port `8000`)

- `POST /v1/admin/tenants/{tenant_id}/provision` (tenant onboarding; creates per-tenant database schema)
- `POST /v1/tenants/{tenant_id}/records` (create an encrypted medical record using AES-256-GCM envelope encryption)
- `GET /v1/tenants/{tenant_id}/records/{record_id}` (decrypt and return the plaintext payload)

All protected endpoints expect `Authorization: Bearer <JWT>`.

