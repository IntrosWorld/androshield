import os
import sqlite3
import tempfile
import threading
import time
import unittest
from io import BytesIO
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException, UploadFile

from app import db, main
from app.analysis_service import AnalysisCapacity


def _analysis(index: int) -> dict:
    return {
        "file": {
            "filename": f"sample-{index}.apk",
            "sha256": f"{index:064x}",
            "md5": f"{index:032x}",
            "file_size": index,
        },
        "manifest": {"package_name": f"org.test.sample{index}"},
        "risk_score": index,
        "severity": "Low",
    }


class SqliteScalabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")
        self.path_patch = patch.object(db, "DB_PATH", self.db_path)
        self.path_patch.start()
        db.init_db()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_wal_indexes_and_paginated_history(self):
        for index in range(3):
            db.save_sample(_analysis(index), {"index": index})
            time.sleep(0.002)

        page = db.list_samples(limit=1, offset=1)
        self.assertEqual(1, len(page))
        self.assertEqual("sample-1.apk", page[0]["filename"])

        connection = sqlite3.connect(self.db_path)
        try:
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            indexes = {
                row[1] for row in connection.execute("PRAGMA index_list('apk_samples')")
            }
        finally:
            connection.close()
        self.assertEqual("wal", journal_mode.lower())
        self.assertIn("idx_apk_samples_upload_time", indexes)
        self.assertIn("idx_apk_samples_sha256", indexes)

    def test_workflow_progress_survives_new_connections(self):
        state = {
            "active": True,
            "phase": "model_wait",
            "events": [{"phase": "tool_selected", "message": "Inspect permissions"}],
        }
        db.save_workflow_progress("case-1", state)
        self.assertEqual(state, db.get_workflow_progress("case-1"))

    def test_restart_marks_incomplete_jobs_as_failed(self):
        job = db.create_analysis_job("queued.apk", active_limit=1)
        self.assertEqual(1, db.count_active_analysis_jobs())
        self.assertIsNone(db.create_analysis_job("rejected.apk", active_limit=1))
        db.update_analysis_job(
            job["id"], status="running", phase="static_analysis",
            message="Running",
        )

        # Simulate a worker lease that stopped receiving progress updates.
        with db._conn() as connection:
            connection.execute(
                db.analysis_jobs.update().where(db.analysis_jobs.c.id == job["id"]).values(
                    updated_at=time.time() - db.ANALYSIS_JOB_STALE_SECONDS - 1
                )
            )

        db.init_db()

        recovered = db.get_analysis_job(job["id"])
        self.assertEqual("failed", recovered["status"])
        self.assertEqual("interrupted", recovered["phase"])
        self.assertEqual(0, db.count_active_analysis_jobs())

    def test_recent_job_is_not_failed_when_another_worker_starts(self):
        job = db.create_analysis_job("live.apk")

        db.init_db()

        self.assertEqual("queued", db.get_analysis_job(job["id"])["status"])

    def test_database_health_does_not_expose_connection_details(self):
        health = db.database_health()
        self.assertEqual("sqlite", health["backend"])
        self.assertTrue(health["reachable"])
        self.assertGreaterEqual(health["latency_ms"], 0)

    def test_hosted_postgres_url_selects_psycopg_without_connecting(self):
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://user:password@example.invalid/app?sslmode=require",
        }):
            normalized = db._database_url()
            engine = db._make_engine(normalized)
        try:
            self.assertTrue(normalized.startswith("postgresql+psycopg://"))
            self.assertEqual("postgresql", engine.dialect.name)
        finally:
            engine.dispose()


class CapacityTests(unittest.TestCase):
    def test_capacity_serializes_work_at_the_configured_limit(self):
        capacity = AnalysisCapacity(1)
        active = 0
        maximum_active = 0
        state_lock = threading.Lock()

        def worker():
            nonlocal active, maximum_active
            with capacity.slot(lambda _phase, _message: None):
                with state_lock:
                    active += 1
                    maximum_active = max(maximum_active, active)
                time.sleep(0.03)
                with state_lock:
                    active -= 1

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(1, maximum_active)
        self.assertEqual({"limit": 1, "active": 0, "waiting": 0}, capacity.snapshot())


class AnalysisJobTests(unittest.IsolatedAsyncioTestCase):
    async def test_queue_limit_rejects_excess_uploads_before_spooling(self):
        upload = UploadFile(filename="sample.apk", file=BytesIO(b"unused"))
        with patch.object(main.static_analyzer, "engine_available", return_value=True), \
             patch.object(
                 main.db, "count_active_analysis_jobs",
                 return_value=main.analysis_service.queue_limit,
             ), \
             patch.object(main, "_spool_upload", new=AsyncMock()) as spool:
            with self.assertRaises(HTTPException) as context:
                await main.create_analysis_job(upload)

        self.assertEqual(429, context.exception.status_code)
        spool.assert_not_awaited()

    async def test_background_job_persists_completion_and_removes_upload(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             patch.object(db, "DB_PATH", os.path.join(temp_dir, "jobs.db")):
            db.init_db()
            job = db.create_analysis_job("sample.apk")
            handle, apk_path = tempfile.mkstemp(suffix=".apk", dir=temp_dir)
            os.close(handle)
            with patch.object(
                main, "run_in_threadpool",
                new=AsyncMock(return_value={"id": "sample-result"}),
            ):
                await main._run_analysis_job(job["id"], apk_path, "sample.apk")

            completed = db.get_analysis_job(job["id"])
            self.assertEqual("completed", completed["status"])
            self.assertEqual("sample-result", completed["sample_id"])
            self.assertFalse(os.path.exists(apk_path))


if __name__ == "__main__":
    unittest.main()
