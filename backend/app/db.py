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


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db():
    with _conn() as con:
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


def list_samples(limit: int = 50):
    with _conn() as con:
        rows = con.execute(
            """SELECT id, filename, sha256, package_name, risk_score, severity, upload_time
               FROM apk_samples ORDER BY upload_time DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
