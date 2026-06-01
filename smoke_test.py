from __future__ import annotations

import os
import subprocess
import sys


REQUIRED_ENV = [
    "JWT_SHARED_SECRET",
    "JWT_ISSUER",
    "KEY_SERVER_DB_DSN",
    "KEY_SERVER_BASE_URL",
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_SSLMODE",
    "TENANT_DB_PREFIX",
]


def main() -> int:
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        print("Missing required environment variables:")
        for k in missing:
            print(f"- {k}")
        print(
            "\nSet them in PowerShell, then run again.\n"
            "Example (adjust passwords/DSN if needed):\n"
            "  $env:JWT_SHARED_SECRET = 'dev_secret_key_hr7382yhf9283yhf'\n"
            "  $env:JWT_ISSUER = 'local-emr-auth-service'\n"
            "  $env:KEY_SERVER_DB_DSN = 'postgresql://postgres:Godisgood1.@127.0.0.1:5432/postgres?sslmode=prefer'\n"
            "  $env:KEY_SERVER_BASE_URL = 'http://127.0.0.1:8001'\n"
            "  $env:POSTGRES_HOST = '127.0.0.1'\n"
            "  $env:POSTGRES_PORT = '5432'\n"
            "  $env:POSTGRES_USER = 'postgres'\n"
            "  $env:POSTGRES_PASSWORD = 'Godisgood1.'\n"
            "  $env:POSTGRES_SSLMODE = 'prefer'\n"
            "  $env:TENANT_DB_PREFIX = 'emr_'\n"
            "\nThen:\n"
            "  python smoke_test.py\n"
        )
        return 2

    # Ensure uvicorn subprocesses can import `apps.*`
    os.environ.setdefault("PYTHONPATH", os.path.abspath(os.getcwd()))

    cmd = [sys.executable, os.path.join("scripts", "smoke_test_workflow.py")]
    print("Running end-to-end smoke test...")
    proc = subprocess.run(cmd, text=True)
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())

