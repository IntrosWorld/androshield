"""Portable persistence for local SQLite and production PostgreSQL.

Set ``DATABASE_URL`` to a PostgreSQL URL (including a Neon URL) in deployed
environments. Without it, the application keeps its zero-setup SQLite database.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from contextlib import contextmanager

from sqlalchemy import (Column, Float, Index, Integer, MetaData, String, Table, Text,
                        create_engine, delete, event, func, insert, select, update)
from sqlalchemy.engine import Engine, URL, make_url
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.pool import NullPool

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "apk_analyzer.db"))
SQLITE_BUSY_TIMEOUT_MS = 5_000
WORKFLOW_PROGRESS_TTL_SECONDS = 7 * 24 * 60 * 60
ANALYSIS_JOB_TTL_SECONDS = 30 * 24 * 60 * 60
ANALYSIS_JOB_STALE_SECONDS = 15 * 60

metadata = MetaData()
apk_samples = Table(
    "apk_samples", metadata,
    Column("id", String, primary_key=True), Column("filename", Text),
    Column("sha256", String(64)), Column("md5", String(32)),
    Column("package_name", Text), Column("version_name", Text),
    Column("file_size", Integer), Column("risk_score", Integer),
    Column("severity", String(16)), Column("upload_time", Float),
    Column("analysis_json", Text), Column("report_json", Text),
)
runtime_settings = Table(
    "runtime_settings", metadata,
    Column("key", String, primary_key=True), Column("value", Text, nullable=False),
    Column("is_secret", Integer, nullable=False, default=0),
    Column("updated_at", Float, nullable=False),
)
workflow_progress = Table(
    "workflow_progress", metadata,
    Column("sample_id", String, primary_key=True),
    Column("state_json", Text, nullable=False), Column("updated_at", Float, nullable=False),
)
analysis_jobs = Table(
    "analysis_jobs", metadata,
    Column("id", String, primary_key=True), Column("filename", Text, nullable=False),
    Column("status", String(16), nullable=False), Column("phase", String(32), nullable=False),
    Column("message", Text, nullable=False), Column("sample_id", String), Column("error", Text),
    Column("created_at", Float, nullable=False), Column("updated_at", Float, nullable=False),
)
Index("idx_apk_samples_upload_time", apk_samples.c.upload_time.desc())
Index("idx_apk_samples_sha256", apk_samples.c.sha256)
Index("idx_analysis_jobs_updated", analysis_jobs.c.updated_at.desc())

_engine_lock = threading.Lock()
_engines: dict[str, Engine] = {}


def _database_url() -> str:
    configured = os.getenv("DATABASE_URL", "").strip()
    if configured:
        # Hosting providers commonly publish either spelling; choose psycopg 3 explicitly.
        if configured.startswith("postgres://"):
            configured = "postgresql+psycopg://" + configured[len("postgres://"):]
        elif configured.startswith("postgresql://"):
            configured = "postgresql+psycopg://" + configured[len("postgresql://"):]
        return configured
    return URL.create("sqlite", database=DB_PATH).render_as_string(hide_password=False)


def _integer_env(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _make_engine(url: str) -> Engine:
    parsed = make_url(url)
    if parsed.get_backend_name() == "sqlite":
        os.makedirs(os.path.dirname(os.path.abspath(parsed.database or DB_PATH)), exist_ok=True)
        engine = create_engine(
            parsed,
            connect_args={"check_same_thread": False, "timeout": SQLITE_BUSY_TIMEOUT_MS / 1000},
            poolclass=NullPool,
        )

        @event.listens_for(engine, "connect")
        def _configure_sqlite(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.close()
        return engine

    if parsed.get_backend_name() != "postgresql":
        raise ValueError("DATABASE_URL must use PostgreSQL; omit it to use local SQLite")
    return create_engine(
        parsed, pool_pre_ping=True,
        pool_size=_integer_env("DATABASE_POOL_SIZE", 5, 1),
        max_overflow=_integer_env("DATABASE_MAX_OVERFLOW", 5, 0),
        pool_recycle=_integer_env("DATABASE_POOL_RECYCLE_SECONDS", 300, 60),
    )


def _engine() -> Engine:
    url = _database_url()
    with _engine_lock:
        if url not in _engines:
            _engines[url] = _make_engine(url)
        return _engines[url]


def backend_name() -> str:
    """Return the active backend without exposing connection credentials."""
    return _engine().dialect.name


@contextmanager
def _conn(*, immediate: bool = False):
    """Yield a transaction; immediate mode makes queue reservation atomic."""
    engine = _engine()
    with engine.connect() as con:
        if immediate and engine.dialect.name == "sqlite":
            con.exec_driver_sql("BEGIN IMMEDIATE")
            transaction = None
        else:
            transaction = con.begin()
        try:
            yield con
            con.commit() if transaction is None else transaction.commit()
        except BaseException:
            con.rollback() if transaction is None else transaction.rollback()
            raise


def init_db():
    engine = _engine()
    if engine.dialect.name == "sqlite":
        with engine.begin() as con:
            con.exec_driver_sql("PRAGMA journal_mode = WAL")
            con.exec_driver_sql("PRAGMA synchronous = NORMAL")
    metadata.create_all(engine)
    now = time.time()
    with _conn() as con:
        # A second API worker must not fail jobs still owned by the first. Recover
        # only leases that have stopped receiving phase/heartbeat updates.
        con.execute(update(analysis_jobs).where(
            analysis_jobs.c.status.in_(("queued", "running")),
            analysis_jobs.c.updated_at < now - ANALYSIS_JOB_STALE_SECONDS,
        ).values(status="failed", phase="interrupted",
                 message="Server stopped before this analysis completed.",
                 error="Analysis interrupted by server restart", updated_at=now))
        con.execute(delete(workflow_progress).where(
            workflow_progress.c.updated_at < now - WORKFLOW_PROGRESS_TTL_SECONDS))
        con.execute(delete(analysis_jobs).where(
            analysis_jobs.c.updated_at < now - ANALYSIS_JOB_TTL_SECONDS))


def database_health() -> dict:
    started = time.perf_counter()
    with _engine().connect() as con:
        con.execute(select(1)).scalar_one()
    return {"backend": backend_name(), "reachable": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2)}


def get_runtime_settings(include_secrets: bool = True) -> dict:
    statement = select(runtime_settings.c.key, runtime_settings.c.value)
    if not include_secrets:
        statement = statement.where(runtime_settings.c.is_secret == 0)
    with _conn() as con:
        rows = con.execute(statement).mappings().all()
    return {row["key"]: row["value"] for row in rows}


def _upsert(con, table: Table, key_column, key_value, values: dict) -> None:
    payload = {key_column.name: key_value, **values}
    dialect_insert = postgresql_insert if con.dialect.name == "postgresql" else sqlite_insert
    statement = dialect_insert(table).values(**payload).on_conflict_do_update(
        index_elements=[key_column], set_=values)
    con.execute(statement)


def save_runtime_settings(values: dict[str, tuple[str, bool]]) -> None:
    now = time.time()
    with _conn() as con:
        for key, (value, secret) in values.items():
            _upsert(con, runtime_settings, runtime_settings.c.key, key,
                    {"value": value, "is_secret": int(secret), "updated_at": now})


def delete_runtime_settings(keys: list[str]) -> None:
    if keys:
        with _conn() as con:
            con.execute(delete(runtime_settings).where(runtime_settings.c.key.in_(keys)))


def save_sample(analysis: dict, report: dict) -> str:
    sample_id = uuid.uuid4().hex[:12]
    file_info, manifest = analysis.get("file", {}), analysis.get("manifest", {})
    with _conn() as con:
        con.execute(insert(apk_samples).values(
            id=sample_id, filename=file_info.get("filename"), sha256=file_info.get("sha256"),
            md5=file_info.get("md5"), package_name=manifest.get("package_name"),
            version_name=manifest.get("version_name"), file_size=file_info.get("file_size"),
            risk_score=analysis.get("risk_score"), severity=analysis.get("severity"),
            upload_time=time.time(), analysis_json=json.dumps(analysis),
            report_json=json.dumps(report)))
    return sample_id


def update_sample_artifacts(sample_id: str, analysis: dict, report: dict) -> bool:
    with _conn() as con:
        result = con.execute(update(apk_samples).where(apk_samples.c.id == sample_id).values(
            analysis_json=json.dumps(analysis), report_json=json.dumps(report)))
    return result.rowcount == 1


def get_sample(sample_id: str):
    with _conn() as con:
        row = con.execute(select(apk_samples).where(apk_samples.c.id == sample_id)).mappings().first()
    if not row:
        return None
    result = dict(row)
    result["analysis"] = json.loads(result.pop("analysis_json") or "{}")
    result["report"] = json.loads(result.pop("report_json") or "{}")
    return result


def list_samples(limit: int = 50, offset: int = 0):
    limit, offset = max(1, min(int(limit), 100)), max(0, int(offset))
    columns = (apk_samples.c.id, apk_samples.c.filename, apk_samples.c.sha256,
               apk_samples.c.package_name, apk_samples.c.risk_score,
               apk_samples.c.severity, apk_samples.c.upload_time)
    with _conn() as con:
        rows = con.execute(select(*columns).order_by(apk_samples.c.upload_time.desc())
                           .limit(limit).offset(offset)).mappings().all()
    return [dict(row) for row in rows]


def save_workflow_progress(sample_id: str, state: dict) -> None:
    with _conn() as con:
        _upsert(con, workflow_progress, workflow_progress.c.sample_id, sample_id,
                {"state_json": json.dumps(state), "updated_at": time.time()})


def get_workflow_progress(sample_id: str) -> dict | None:
    with _conn() as con:
        state = con.execute(select(workflow_progress.c.state_json).where(
            workflow_progress.c.sample_id == sample_id)).scalar_one_or_none()
    return json.loads(state) if state else None


def create_analysis_job(filename: str, *, active_limit: int | None = None) -> dict | None:
    """Atomically reserve a queue slot across threads and API processes."""
    job_id, now = uuid.uuid4().hex[:16], time.time()
    with _conn(immediate=True) as con:
        if con.dialect.name == "postgresql":
            con.exec_driver_sql("SELECT pg_advisory_xact_lock(hashtext('apk-analysis-queue'))")
        if active_limit is not None:
            active = con.execute(select(func.count()).select_from(analysis_jobs).where(
                analysis_jobs.c.status.in_(("queued", "running")))).scalar_one()
            if int(active) >= active_limit:
                return None
        con.execute(insert(analysis_jobs).values(
            id=job_id, filename=filename, status="queued", phase="queued",
            message="Waiting for analysis capacity.", created_at=now, updated_at=now))
    return get_analysis_job(job_id)


def update_analysis_job(job_id: str, **values) -> bool:
    allowed = {"status", "phase", "message", "sample_id", "error"}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"unsupported analysis job field: {sorted(unknown)[0]}")
    if not values:
        return False
    values["updated_at"] = time.time()
    with _conn() as con:
        result = con.execute(update(analysis_jobs).where(
            analysis_jobs.c.id == job_id).values(**values))
    return result.rowcount == 1


def get_analysis_job(job_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute(select(analysis_jobs).where(
            analysis_jobs.c.id == job_id)).mappings().first()
    return dict(row) if row else None


def count_active_analysis_jobs() -> int:
    with _conn() as con:
        count = con.execute(select(func.count()).select_from(analysis_jobs).where(
            analysis_jobs.c.status.in_(("queued", "running")))).scalar_one()
    return int(count)
