"""Copy the existing local SQLite history into PostgreSQL.

Runtime settings are excluded unless explicitly requested because they may contain
API keys. Re-running the command is safe: existing primary keys are skipped.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sqlalchemy import MetaData, create_engine, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app import db  # noqa: E402

MIGRATION_BATCH_SIZE = 100


def migrate(source: Path, target_url: str, *, include_settings: bool, dry_run: bool) -> dict:
    if not source.is_file():
        raise FileNotFoundError(f"SQLite database not found: {source}")
    target_url = target_url.strip()
    if target_url.startswith("postgres://"):
        target_url = "postgresql+psycopg://" + target_url[len("postgres://"):]
    elif target_url.startswith("postgresql://"):
        target_url = "postgresql+psycopg://" + target_url[len("postgresql://"):]
    if not target_url.startswith("postgresql+psycopg://"):
        raise ValueError("--target must be a PostgreSQL connection URL")

    source_engine = create_engine(f"sqlite:///{source.resolve().as_posix()}")
    target_engine = None if dry_run else create_engine(target_url, pool_pre_ping=True)
    if target_engine is not None:
        db.metadata.create_all(target_engine)
    reflected = MetaData()
    reflected.reflect(source_engine)
    table_names = ["apk_samples", "workflow_progress", "analysis_jobs"]
    if include_settings:
        table_names.append("runtime_settings")
    counts: dict[str, int] = {}

    with source_engine.connect() as source_connection:
        for name in table_names:
            if name not in reflected.tables:
                counts[name] = 0
                continue
            rows = [dict(row) for row in source_connection.execute(
                select(reflected.tables[name])
            ).mappings()]
            counts[name] = len(rows)
            if dry_run or not rows:
                continue
            target_table = db.metadata.tables[name]
            primary_keys = [column.name for column in target_table.primary_key.columns]
            for start in range(0, len(rows), MIGRATION_BATCH_SIZE):
                batch = rows[start:start + MIGRATION_BATCH_SIZE]
                statement = postgresql_insert(target_table).values(batch).on_conflict_do_nothing(
                    index_elements=primary_keys
                )
                with target_engine.begin() as target_connection:
                    target_connection.execute(statement)

    source_engine.dispose()
    if target_engine is not None:
        target_engine.dispose()
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(db.DB_PATH))
    parser.add_argument("--target", default=os.getenv("DATABASE_URL", ""))
    parser.add_argument("--include-runtime-settings", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.target:
        parser.error("provide --target or set DATABASE_URL")
    counts = migrate(args.source, args.target,
                     include_settings=args.include_runtime_settings, dry_run=args.dry_run)
    action = "Would migrate" if args.dry_run else "Migrated"
    print(f"{action}: " + ", ".join(f"{name}={count}" for name, count in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
