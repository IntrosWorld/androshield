import os
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from io import BytesIO
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException, UploadFile

from app import db, main
from app.analyzer import yara_scan
from app.analysis_service import AnalysisCapacity
from app.intel import apkid_scan
from app.ml import classifier


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

    def test_batch_queue_reservation_is_atomic(self):
        jobs = db.create_analysis_jobs(
            ["first.apk", "second.apk"], active_limit=2,
        )

        self.assertEqual(2, len(jobs))
        self.assertEqual({"first.apk", "second.apk"}, {job["filename"] for job in jobs})
        self.assertEqual(2, db.count_active_analysis_jobs())
        self.assertIsNone(db.create_analysis_jobs(["third.apk"], active_limit=2))

    def test_folder_batch_history_groups_jobs_and_filters_single_history(self):
        batch = db.create_analysis_batch(
            "mixed-folder",
            ["benign.apk", "risk.apk"],
            ["mixed-folder/benign.apk", "mixed-folder/risk.apk"],
            active_limit=2,
        )
        benign_id = db.save_sample(_analysis(8), {})
        risky = _analysis(75)
        risky["severity"] = "Critical"
        risky_id = db.save_sample(risky, {})
        db.update_analysis_job(
            batch["jobs"][0]["id"], status="completed", phase="completed",
            message="Done", sample_id=benign_id,
        )
        db.update_analysis_job(
            batch["jobs"][1]["id"], status="completed", phase="completed",
            message="Done", sample_id=risky_id,
        )

        history = db.list_analysis_batches()
        self.assertEqual(1, len(history))
        self.assertEqual("mixed-folder", history[0]["folder_name"])
        self.assertEqual(2, history[0]["completed"])
        self.assertEqual(1, history[0]["flagged"])
        self.assertEqual(75, history[0]["max_score"])
        self.assertEqual("Critical", history[0]["max_severity"])
        detail = db.get_analysis_batch(batch["id"])
        self.assertEqual(2, len(detail["items"]))
        self.assertEqual([], db.list_samples(exclude_batch=True))
        self.assertEqual(2, len(db.list_samples()))

    def test_rejected_folder_batch_does_not_leave_history(self):
        self.assertIsNone(db.create_analysis_batch(
            "too-large", ["one.apk", "two.apk"],
            ["too-large/one.apk", "too-large/two.apk"], active_limit=1,
        ))
        self.assertEqual([], db.list_analysis_batches())

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

    def test_progress_failure_does_not_leak_waiting_capacity(self):
        capacity = AnalysisCapacity(1)

        def failed_progress(_phase, _message):
            raise RuntimeError("progress unavailable")

        with self.assertRaisesRegex(RuntimeError, "progress unavailable"):
            with capacity.slot(failed_progress):
                self.fail("slot must not be entered when progress reporting fails")

        self.assertEqual({"limit": 1, "active": 0, "waiting": 0}, capacity.snapshot())
        with capacity.slot(lambda _phase, _message: None):
            self.assertEqual(1, capacity.snapshot()["active"])


class ConcurrentLazyLoadTests(unittest.TestCase):
    @staticmethod
    def _run_concurrent(loader, started, release):
        results = []
        threads = [threading.Thread(target=lambda: results.append(loader())) for _ in range(2)]
        threads[0].start()
        if not started.wait(1):
            release.set()
            raise AssertionError("lazy loader did not start")
        threads[1].start()
        time.sleep(0.02)
        release.set()
        for thread in threads:
            thread.join(1)
        return results

    def test_yara_rules_are_published_only_after_compile_finishes(self):
        started, release = threading.Event(), threading.Event()
        compiled = object()
        fake_yara = types.ModuleType("yara")

        def compile_rules(**_kwargs):
            started.set()
            release.wait(1)
            return compiled

        fake_yara.compile = compile_rules
        with patch.dict(sys.modules, {"yara": fake_yara}), \
             patch.object(yara_scan, "_compiled", None), \
             patch.object(yara_scan, "_load_attempted", False):
            results = self._run_concurrent(yara_scan._rules, started, release)

        self.assertEqual([compiled, compiled], results)

    def test_apkid_scanner_is_published_only_after_rules_finish_loading(self):
        started, release = threading.Event(), threading.Event()
        fake_package = types.ModuleType("apkid")
        fake_package.__path__ = []
        fake_apkid = types.ModuleType("apkid.apkid")
        fake_rules = types.ModuleType("apkid.rules")

        class Options:
            def __init__(self, **_kwargs):
                pass

        class Scanner:
            def __init__(self, rules, _options):
                self.rules = rules

        class RulesManager:
            def load(self):
                started.set()
                release.wait(1)
                return object()

        fake_apkid.Options, fake_apkid.Scanner = Options, Scanner
        fake_rules.RulesManager = RulesManager
        with patch.dict(sys.modules, {
            "apkid": fake_package, "apkid.apkid": fake_apkid, "apkid.rules": fake_rules,
        }), patch.object(apkid_scan, "_scanner", None), \
             patch.object(apkid_scan, "_load_attempted", False):
            results = self._run_concurrent(apkid_scan._get_scanner, started, release)

        self.assertEqual(2, len(results))
        self.assertIs(results[0], results[1])

    def test_ml_bundle_is_published_only_after_deserialization_finishes(self):
        import joblib
        # Warm scikit-learn's own lazy imports on the main thread; this test targets
        # our bundle publication lock, not SciPy's module initialisation.
        from sklearn.exceptions import InconsistentVersionWarning  # noqa: F401

        started, release = threading.Event(), threading.Event()
        bundle = {"model": object(), "vocabulary": []}

        def load_bundle(_path):
            started.set()
            release.wait(1)
            return bundle

        with patch.object(joblib, "load", side_effect=load_bundle), \
             patch.object(classifier, "_bundle", None), \
             patch.object(classifier, "_load_attempted", False):
            results = self._run_concurrent(classifier._load, started, release)

        self.assertEqual([bundle, bundle], results)


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

    async def test_folder_batch_queues_each_apk_through_existing_workers(self):
        uploads = [
            UploadFile(filename="folder/first.apk", file=BytesIO(b"first")),
            UploadFile(filename="folder/second.apk", file=BytesIO(b"second")),
        ]
        handles = [tempfile.NamedTemporaryFile(suffix=".apk", delete=False) for _ in uploads]
        paths = [handle.name for handle in handles]
        for handle in handles:
            handle.close()
        jobs = [
            {"id": "job-1", "filename": "first.apk", "status": "queued"},
            {"id": "job-2", "filename": "second.apk", "status": "queued"},
        ]
        try:
            with patch.object(main.static_analyzer, "engine_available", return_value=True), \
                 patch.object(main.db, "count_active_analysis_jobs", return_value=0), \
                 patch.object(main.db, "create_analysis_batch", return_value={
                     "id": "batch-1", "folder_name": "folder", "jobs": jobs,
                 }) as reserve, \
                 patch.object(
                     main, "_spool_upload",
                     new=AsyncMock(side_effect=[(paths[0], 5), (paths[1], 6)]),
                 ), \
                 patch.object(main, "_start_analysis_job") as start:
                result = await main.create_batch_analysis_jobs(
                    uploads,
                    folder_name="folder",
                    relative_paths='["folder/first.apk", "folder/second.apk"]',
                )

            self.assertEqual(2, result["count"])
            reserve.assert_called_once_with(
                "folder",
                ["first.apk", "second.apk"],
                ["folder/first.apk", "folder/second.apk"],
                active_limit=main.analysis_service.queue_limit,
            )
            self.assertEqual("batch-1", result["batch_id"])
            self.assertEqual(2, start.call_count)
            start.assert_any_call("job-1", paths[0], "first.apk")
            start.assert_any_call("job-2", paths[1], "second.apk")
        finally:
            for path in paths:
                if os.path.exists(path):
                    os.remove(path)

    async def test_folder_batch_rejects_over_limit_before_spooling(self):
        uploads = [
            UploadFile(filename="first.apk", file=BytesIO(b"first")),
            UploadFile(filename="second.apk", file=BytesIO(b"second")),
        ]
        with patch.object(main, "MAX_BATCH_APKS", 1), \
             patch.object(main.static_analyzer, "engine_available", return_value=True), \
             patch.object(main, "_spool_upload", new=AsyncMock()) as spool:
            with self.assertRaises(HTTPException) as context:
                await main.create_batch_analysis_jobs(
                    uploads, folder_name="folder", relative_paths="[]",
                )

        self.assertEqual(413, context.exception.status_code)
        spool.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
