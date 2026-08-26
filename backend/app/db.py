"""Minimal SQLite persistence (stdlib only — no Postgres setup needed for the MVP).

Stores one row per analysed APK with the full analysis + report JSON blobs so the
dashboard history and report export can be reconstructed.
"""
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "apk_analyzer.db")
DB_PATH = os.path.abspath(DB_PATH)
SQLITE_BUSY_TIMEOUT_MS = 5_000
WORKFLOW_PROGRESS_TTL_SECONDS = 7 * 24 * 60 * 60
ANALYSIS_JOB_TTL_SECONDS = 30 * 24 * 60 * 60


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
    con.row_factory = sqlite3.Row
    con.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db():
    with _conn() as con:
        # WAL permits readers while an analysis or workflow update is being written.
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA synchronous = NORMAL")
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS apk_samples (
                id            TEXT PRIMARY KEY,
                filename      TEXT,
                sha256        TEXT,
                md5           TEXT,
                package_name  TEXT,
                version_name  TEXT,
                file_size     INTEGER,
                risk_score    INTEGER,
                severity      TEXT,
                upload_time   REAL,
                analysis_json TEXT,
                report_json   TEXT
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_settings (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                is_secret  INTEGER NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS workflow_progress (
                sample_id  TEXT PRIMARY KEY,
                state_json TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                id         TEXT PRIMARY KEY,
                filename   TEXT NOT NULL,
                status     TEXT NOT NULL,
                phase      TEXT NOT NULL,
                message    TEXT NOT NULL,
                sample_id  TEXT,
                error      TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_apk_samples_upload_time "
            "ON apk_samples(upload_time DESC)"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_apk_samples_sha256 ON apk_samples(sha256)"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_updated "
            "ON analysis_jobs(updated_at DESC)"
        )
        now = time.time()
        con.execute(
            """UPDATE analysis_jobs
               SET status = 'failed', phase = 'interrupted',
                   message = 'Server restarted before this analysis completed.',
                   error = 'Analysis interrupted by server restart', updated_at = ?
               WHERE status IN ('queued', 'running')""",
            (now,),
        )
        con.execute(
            "DELETE FROM workflow_progress WHERE updated_at < ?",
            (now - WORKFLOW_PROGRESS_TTL_SECONDS,),
        )
        con.execute(
            "DELETE FROM analysis_jobs WHERE updated_at < ?",
            (now - ANALYSIS_JOB_TTL_SECONDS,),
        )


def get_runtime_settings(include_secrets: bool = True) -> dict:
    """Return locally persisted runtime settings.

    Callers serving HTTP responses must leave ``include_secrets`` false. The default
    is intended for the startup loader, which applies values directly to the process.
    """
    with _conn() as con:
        if include_secrets:
            rows = con.execute("SELECT key, value FROM runtime_settings").fetchall()
        else:
            rows = con.execute(
                "SELECT key, value FROM runtime_settings WHERE is_secret = 0"
            ).fetchall()
    return {row["key"]: row["value"] for row in rows}


def save_runtime_settings(values: dict[str, tuple[str, bool]]) -> None:
    now = time.time()
    with _conn() as con:
        con.executemany(
            """INSERT INTO runtime_settings (key, value, is_secret, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   is_secret = excluded.is_secret,
                   updated_at = excluded.updated_at""",
            [(key, value, int(secret), now) for key, (value, secret) in values.items()],
        )


def delete_runtime_settings(keys: list[str]) -> None:
    if not keys:
        return
    with _conn() as con:
        con.executemany("DELETE FROM runtime_settings WHERE key = ?", [(key,) for key in keys])


def save_sample(analysis: dict, report: dict) -> str:
    sample_id = uuid.uuid4().hex[:12]
    f = analysis.get("file", {})
    m = analysis.get("manifest", {})
    with _conn() as con:
        con.execute(
            """INSERT INTO apk_samples
               (id, filename, sha256, md5, package_name, version_name, file_size,
                risk_score, severity, upload_time, analysis_json, report_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sample_id,
                f.get("filename"),
                f.get("sha256"),
                f.get("md5"),
                m.get("package_name"),
                m.get("version_name"),
                f.get("file_size"),
                analysis.get("risk_score"),
                analysis.get("severity"),
                time.time(),
                json.dumps(analysis),
                json.dumps(report),
            ),
        )
    return sample_id


def update_sample_artifacts(sample_id: str, analysis: dict, report: dict) -> bool:
    """Persist a post-analysis agent investigation/report refresh."""
    with _conn() as con:
        cur = con.execute(
            """UPDATE apk_samples
               SET analysis_json = ?, report_json = ?
               WHERE id = ?""",
            (json.dumps(analysis), json.dumps(report), sample_id),
        )
    return cur.rowcount == 1


def get_sample(sample_id: str):
    with _conn() as con:
        row = con.execute("SELECT * FROM apk_samples WHERE id = ?", (sample_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["analysis"] = json.loads(d.pop("analysis_json") or "{}")
    d["report"] = json.loads(d.pop("report_json") or "{}")
    return d


def list_samples(limit: int = 50, offset: int = 0):
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    with _conn() as con:
        rows = con.execute(
            """SELECT id, filename, sha256, package_name, risk_score, severity, upload_time
               FROM apk_samples ORDER BY upload_time DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def save_workflow_progress(sample_id: str, state: dict) -> None:
    """Persist bounded live workflow state so polling survives a server restart."""
    now = time.time()
    with _conn() as con:
        con.execute(
            """INSERT INTO workflow_progress (sample_id, state_json, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(sample_id) DO UPDATE SET
                   state_json = excluded.state_json,
                   updated_at = excluded.updated_at""",
            (sample_id, json.dumps(state), now),
        )


def get_workflow_progress(sample_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute(
            "SELECT state_json FROM workflow_progress WHERE sample_id = ?",
            (sample_id,),
        ).fetchone()
    return json.loads(row["state_json"]) if row else None


def create_analysis_job(filename: str, *, active_limit: int | None = None) -> dict | None:
    """Reserve a queue slot atomically, returning ``None`` when capacity is full."""
    job_id = uuid.uuid4().hex[:16]
    now = time.time()
    with _conn() as con:
        con.execute("BEGIN IMMEDIATE")
        if active_limit is not None:
            row = con.execute(
                """SELECT COUNT(*) AS count FROM analysis_jobs
                   WHERE status IN ('queued', 'running')"""
            ).fetchone()
            if int(row["count"]) >= active_limit:
                return None
        con.execute(
            """INSERT INTO analysis_jobs
               (id, filename, status, phase, message, created_at, updated_at)
               VALUES (?, ?, 'queued', 'queued', 'Waiting for analysis capacity.', ?, ?)""",
            (job_id, filename, now, now),
        )
    return get_analysis_job(job_id)


def update_analysis_job(job_id: str, **values) -> bool:
    allowed = {"status", "phase", "message", "sample_id", "error"}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"unsupported analysis job field: {sorted(unknown)[0]}")
    if not values:
        return False
    values["updated_at"] = time.time()
    assignments = ", ".join(f"{key} = ?" for key in values)
    with _conn() as con:
        cursor = con.execute(
            f"UPDATE analysis_jobs SET {assignments} WHERE id = ?",
            (*values.values(), job_id),
        )
    return cursor.rowcount == 1


def get_analysis_job(job_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute(
            """SELECT id, filename, status, phase, message, sample_id, error,
                      created_at, updated_at
               FROM analysis_jobs WHERE id = ?""",
            (job_id,),
        ).fetchone()
    return dict(row) if row else None


def count_active_analysis_jobs() -> int:
    with _conn() as con:
        row = con.execute(
            "SELECT COUNT(*) AS count FROM analysis_jobs WHERE status IN ('queued', 'running')"
        ).fetchone()
    return int(row["count"])
