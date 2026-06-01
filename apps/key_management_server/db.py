from __future__ import annotations

import os
from typing import Any

import psycopg
from psycopg.rows import dict_row


def _key_server_dsn() -> str:
    dsn = os.getenv("KEY_SERVER_DB_DSN")
    if not dsn:
        raise RuntimeError("KEY_SERVER_DB_DSN env var must be set (e.g. postgres://user:pass@host:5432/key_management)")
    return dsn


def connect_sync() -> psycopg.Connection[Any]:
    return psycopg.connect(
        _key_server_dsn(),
        row_factory=dict_row,
        autocommit=True,
    )


def init_db_sync() -> None:
    conn = connect_sync()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                create table if not exists tenant_master_keys (
                    id bigserial primary key,
                    tenant_id text not null,
                    key_version bigint not null,
                    public_key_pem text not null,
                    private_key_pem text not null,
                    is_active boolean not null default false,
                    created_at timestamptz not null default now()
                );
                """
            )
            # Enforce single active master key per tenant.
            cur.execute(
                """
                create unique index if not exists tenant_active_master_key_idx
                on tenant_master_keys (tenant_id)
                where is_active = true;
                """
            )

            cur.execute(
                """
                create table if not exists audit_events (
                    id bigserial primary key,
                    created_at timestamptz not null default now(),
                    actor_sub text not null,
                    tenant_id text not null,
                    operation text not null,
                    status text not null,
                    key_version bigint null
                );
                """
            )
    finally:
        conn.close()


def get_active_master_key(conn: psycopg.Connection[Any], tenant_id: str) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """
            select tenant_id, key_version, public_key_pem, private_key_pem, is_active
            from tenant_master_keys
            where tenant_id = %s and is_active = true
            limit 1;
            """,
            (tenant_id,),
        )
        row = cur.fetchone()
        if not row:
            raise ValueError(f"No active master key for tenant_id={tenant_id}")
        return row


def get_master_key_by_version(
    conn: psycopg.Connection[Any],
    *,
    tenant_id: str,
    key_version: int,
) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """
            select tenant_id, key_version, public_key_pem, private_key_pem, is_active
            from tenant_master_keys
            where tenant_id = %s and key_version = %s
            limit 1;
            """,
            (tenant_id, key_version),
        )
        row = cur.fetchone()
        if not row:
            raise ValueError(f"No master key for tenant_id={tenant_id} key_version={key_version}")
        return row


def create_master_key(
    conn: psycopg.Connection[Any],
    tenant_id: str,
    *,
    public_key_pem: str,
    private_key_pem: str,
) -> int:
    """
    Creates a new RSA master key encryption key for a tenant and activates it.
    """
    with conn.cursor() as cur:
        # Determine next key_version for this tenant.
        cur.execute(
            """
            select coalesce(max(key_version), 0) + 1 as next_version
            from tenant_master_keys
            where tenant_id = %s;
            """,
            (tenant_id,),
        )
        row = cur.fetchone()
        next_version = int(row["next_version"])

        cur.execute(
            """
            update tenant_master_keys
            set is_active = false
            where tenant_id = %s;
            """,
            (tenant_id,),
        )

        cur.execute(
            """
            insert into tenant_master_keys (tenant_id, key_version, public_key_pem, private_key_pem, is_active)
            values (%s, %s, %s, %s, true)
            returning key_version;
            """,
            (tenant_id, next_version, public_key_pem, private_key_pem),
        )
        inserted = cur.fetchone()
        return int(inserted["key_version"])


def record_audit_event(
    conn: psycopg.Connection[Any],
    *,
    actor_sub: str,
    tenant_id: str,
    operation: str,
    status: str,
    key_version: int | None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into audit_events (actor_sub, tenant_id, operation, status, key_version)
            values (%s, %s, %s, %s, %s);
            """,
            (actor_sub, tenant_id, operation, status, key_version),
        )

