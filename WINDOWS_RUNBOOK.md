# Windows Runbook (How to Run + Demo This Project)

This guide is for someone who **did not build the project** and needs to **run it on a Windows laptop** and **demo it to professors**.

## What this project is (1 minute explanation)

This system secures Electronic Medical Records (EMRs) using:

- **Core Medical Application API** (port `8000`): stores and retrieves EMR records
- **Standalone Key Management Server (KMS)** (port `8001`): generates and unwraps encryption keys
- **PostgreSQL database-per-tenant**: each tenant/clinic gets an isolated database (e.g., `emr_tenant_101`)
- **Envelope encryption**:
  - EMR payload encrypted with **AES-256-GCM**
  - The per-record Data Encryption Key (DEK) is protected by the KMS using **RSA-OAEP**
- **JWT Bearer tokens** for authorization:
  - JWT includes `iss`, `sub`, and `tenant_id`
  - Requests are rejected if JWT `tenant_id` doesn’t match the `{tenant_id}` in the URL

## 0) Prerequisites

Install and confirm:

- **Python 3.11+**
  - Check: `python --version`
- **PostgreSQL** running locally
  - Check: server running and reachable on `127.0.0.1:5432`

## 1) Download the project

Option A: Git clone (recommended)

```powershell
git clone <REPO_URL>
cd dennis
```

Option B: Download ZIP

- Download ZIP from GitHub
- Extract it
- Open PowerShell **inside the extracted folder** (the folder containing `requirements.txt`)

## 2) Install Python dependencies

From the project folder:

```powershell
python -m pip install -r requirements.txt
```

## 3) Set required environment variables (PowerShell)

In PowerShell (same window you’ll run commands from), set:

```powershell
export JWT_SHARED_SECRET='dev_secret_key_hr7382yhf9283yhf'
export JWT_ISSUER='local-emr-auth-service'

# PostgreSQL connection used by Core API to provision and connect to per-tenant DBs
export POSTGRES_HOST='127.0.0.1'
export POSTGRES_PORT='5432'
export POSTGRES_USER='postgres'
export POSTGRES_PASSWORD='Godisgood1.'
export POSTGRES_SSLMODE='prefer'
export TENANT_DB_PREFIX='emr_'
export LOG_ENCRYPTION_KEY="kTOuXk9feQHpXZMQeUdbLM35gsApgD8A0G9e8nyMoyY="

# KMS database connection (stores tenant master keys + audit events)
export KEY_SERVER_DB_DSN='postgresql://postgres:Godisgood1.@127.0.0.1:5432/postgres?sslmode=prefer'

# Where Core API calls the KMS
export KEY_SERVER_BASE_URL='http://127.0.0.1:8001'
```

## 4) Quick verification (one command)

This runs the full workflow automatically:

```powershell
python smoke_test.py
```

Expected output includes:

- `smoke_test_workflow: PASS`

If you get `PASS`, the end-to-end system is working.

## 5) Run servers (for a live demo via browser)

Open **two PowerShell windows** in the project folder.

### Terminal A — Start KMS (port 8001)

```powershell
python -m uvicorn apps.key_management_server.main:app --host 127.0.0.1 --port 8001 --reload
```

### Terminal B — Start Core API (port 8000)

```powershell
python -m uvicorn apps.core_app.main:app --host 127.0.0.1 --port 8000 --reload
```

If both are running, you can open:

- **Core API docs**: `http://127.0.0.1:8000/docs`
- **KMS docs**: `http://127.0.0.1:8001/docs`

## 6) Generate a JWT (for Authorization)

Run:

```powershell
python -c "import jwt; print(jwt.encode({'iss':'local-emr-auth-service','sub':'clinician_uuid_456','tenant_id':'tenant_101'}, 'dev_secret_key_hr7382yhf9283yhf', algorithm='HS256'))"
```

Copy the printed token.

In each `/docs` page:

- Click **Authorize**
- Paste: `Bearer <PASTE_TOKEN>`
- Click **Authorize**

## 7) Demo script (what to click in `/docs`)

Use tenant ID: `tenant_101` (must match the JWT `tenant_id` claim).

### Step 1 — Rotate tenant master key (KMS)

In `http://127.0.0.1:8001/docs`

- Find: `POST /v1/tenants/{tenant_id}/master-keys/rotate`
- Click **Try it out**
- Set `tenant_id` = `tenant_101`
- Click **Execute**

Expected: `200` response like `{ "tenant_id": "tenant_101", "key_version": 1 }` (or higher).

### Step 2 — Provision tenant database (Core API)

In `http://127.0.0.1:8000/docs`

- Find: `POST /v1/admin/tenants/{tenant_id}/provision`
- **Try it out**
- `tenant_id` = `tenant_101`
- **Execute**

Expected: `201` response like `{ "tenant_id": "tenant_101" }`

### Step 3 — Create an encrypted record (Core API)

- Find: `POST /v1/tenants/{tenant_id}/records`
- **Try it out**
- `tenant_id` = `tenant_101`
- Body:

```json
{
  "encrypted_dek_hex": "string",
  "ciphertext_hex": "string",
  "iv_hex": "string",
  "tag_hex": "string",        
  "payload_meta": {},
  "plaintext": "demo record"
}
```

- **Execute**

Expected: `201` response with a `record_id` (UUID). Copy it.

### Step 4 — Retrieve and decrypt the record (Core API)

- Find: `GET /v1/tenants/{tenant_id}/records/{record_id}`
- **Try it out**
- `tenant_id` = `tenant_101`
- `record_id` = (paste the UUID)
- **Execute**

Expected: `200` response like:

```json
{
  "record_id": "<same uuid>",
  "plaintext": "demo record"
}
```

## 8) Extra proof (tenant isolation)

Generate a token for a different tenant (tenant_999):

```powershell
python -c "import jwt; print(jwt.encode({'iss':'local-emr-auth-service','sub':'clinician_uuid_456','tenant_id':'tenant_999'}, 'dev_secret_key_hr7382yhf9283yhf', algorithm='HS256'))"
```

Authorize with that token, then call an endpoint using URL tenant `tenant_101`.

Expected: **403** with `Tenant claim mismatch`.

## Troubleshooting

### “python is not recognized”

Install Python and check “Add to PATH”.

### “could not connect to server” (PostgreSQL)

Start PostgreSQL and confirm it is listening on `127.0.0.1:5432`.

### Authentication failures (PostgreSQL)

Ensure `POSTGRES_USER` / `POSTGRES_PASSWORD` match your local PostgreSQL user.
Also update `KEY_SERVER_DB_DSN` to match.

### Ports already in use (8000/8001)

Stop previous servers or change ports in the uvicorn commands.

