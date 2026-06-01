from __future__ import annotations

import os
from uuid import UUID
from typing import Any

import psycopg
from psycopg.rows import dict_row


def _env_required(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"{name} env var must be set")
    return v


def _tenant_db_prefix() -> str:
    return os.getenv("TENANT_DB_PREFIX", "emr_")


def _tenant_db_name(tenant_id: str) -> str:
    # The document specifies database-per-tenant (logical separation).
    return f"{_tenant_db_prefix()}{tenant_id}"


def _common_conn_info() -> tuple[str, str, str, str, str]:
    host = _env_required("POSTGRES_HOST")
    port = os.getenv("POSTGRES_PORT", "5432")
    user = _env_required("POSTGRES_USER")
    password = _env_required("POSTGRES_PASSWORD")
    sslmode = os.getenv("POSTGRES_SSLMODE", "prefer")
    return host, port, user, password, sslmode


def _dsn_for_db(db_name: str) -> str:
    host, port, user, password, sslmode = _common_conn_info()
    # Avoids needing a templated full DSN string.
    return f"postgresql://{user}:{password}@{host}:{port}/{db_name}?sslmode={sslmode}"


def connect_tenant_sync(tenant_id: str) -> psycopg.Connection[Any]:
    db_name = _tenant_db_name(tenant_id)
    return psycopg.connect(_dsn_for_db(db_name), row_factory=dict_row, autocommit=True)


def connect_admin_db_sync() -> psycopg.Connection[Any]:
    # Uses the default 'postgres' maintenance database for provisioning.
    return psycopg.connect(_dsn_for_db("postgres"), row_factory=dict_row, autocommit=True)


def init_tenant_schema_sync(conn: psycopg.Connection[Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            create table if not exists patient_records (
                record_id uuid primary key,
                ciphertext bytea not null,
                auth_tag bytea not null,
                iv bytea not null,
                dek_encrypted bytea not null,
                dek_key_version bigint not null,
                created_at timestamptz not null default now()
            );
            """
        )
        cur.execute(
            """
            create table if not exists access_audit (
                id bigserial primary key,
                created_at timestamptz not null default now(),
                actor_sub text not null,
                tenant_id text not null,
                operation text not null,
                status text not null,
                record_id uuid null
            );
            """
        )


def provision_tenant_database_sync(tenant_id: str) -> None:
    db_name = _tenant_db_name(tenant_id)
    with connect_admin_db_sync() as conn:
        with conn.cursor() as cur:
            cur.execute("select 1 from pg_database where datname = %s;", (db_name,))
            row = cur.fetchone()
            if not row:
                # Quote the identifier to safely handle tenant-derived names.
                cur.execute(f'create database "{db_name}"')

    # Initialize schema in the new tenant DB.
    with connect_tenant_sync(tenant_id) as tenant_conn:
        init_tenant_schema_sync(tenant_conn)


def create_patient_record(
    conn: psycopg.Connection[Any],
    *,
    record_id: UUID,
    ciphertext: bytes,
    auth_tag: bytes,
    iv: bytes,
    dek_encrypted: bytes,
    dek_key_version: int,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into patient_records
                (record_id, ciphertext, auth_tag, iv, dek_encrypted, dek_key_version)
            values
                (%s, %s, %s, %s, %s, %s);
            """,
            (record_id, ciphertext, auth_tag, iv, dek_encrypted, dek_key_version),
        )


def get_patient_record(
    conn: psycopg.Connection[Any],
    *,
    record_id: UUID,
) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """
            select record_id, ciphertext, auth_tag, iv, dek_encrypted, dek_key_version
            from patient_records
            where record_id = %s;
            """,
            (record_id,),
        )
        row = cur.fetchone()
        if not row:
            raise KeyError(f"record_id={record_id} not found")
        return row


def audit_access_event(
    conn: psycopg.Connection[Any],
    *,
    actor_sub: str,
    tenant_id: str,
    operation: str,
    status: str,
    record_id: UUID | None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into access_audit (actor_sub, tenant_id, operation, status, record_id)
            values (%s, %s, %s, %s, %s);
            """,
            (actor_sub, tenant_id, operation, status, record_id),
        )

