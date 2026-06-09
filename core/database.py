"""SQLite session helpers."""
import os
from contextlib import contextmanager

from sqlmodel import Session, SQLModel, create_engine

from core.config import settings

# For sqlite paths, ensure parent dir exists
if settings.database_url.startswith("sqlite:///"):
    path = settings.database_url.replace("sqlite:///", "", 1)
    if path.startswith("/"):
        os.makedirs(os.path.dirname(path), exist_ok=True)

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
    echo=False,
)


def init_db() -> None:
    # Import models so SQLModel metadata is populated
    from core import models  # noqa: F401
    SQLModel.metadata.create_all(engine)
    _migrate_add_missing_columns()


def _migrate_add_missing_columns() -> None:
    """Add columns introduced after a table was first created.

    `SQLModel.metadata.create_all` only CREATEs missing tables -- it does NOT
    ALTER an existing table to add new columns. Upgrading instances therefore
    keep their old `discoveredhost` schema and would crash on the new
    declarative-management columns. This performs idempotent additive-only
    `ALTER TABLE ... ADD COLUMN` migrations (safe + non-destructive on SQLite).
    """
    from sqlalchemy import inspect, text

    # column_name -> SQL type/default clause to add when missing.
    wanted = {
        "discoveredhost": {
            "managed": "BOOLEAN NOT NULL DEFAULT 0",
            "desired_type": "VARCHAR NOT NULL DEFAULT 'A'",
            "desired_proxied": "BOOLEAN",
            "desired_ttl": "INTEGER",
            "desired_content": "VARCHAR",
            "managed_record_id": "VARCHAR",
            "last_reconcile_error": "VARCHAR",
        },
    }
    try:
        insp = inspect(engine)
        existing_tables = set(insp.get_table_names())
        with engine.begin() as conn:
            for table, cols in wanted.items():
                if table not in existing_tables:
                    continue  # create_all already built it with all columns
                have = {c["name"] for c in insp.get_columns(table)}
                for col, ddl in cols.items():
                    if col not in have:
                        conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {col} {ddl}'))
    except Exception:
        # Best-effort: never block startup on a migration hiccup. A fresh DB
        # already has the columns from create_all; a broken ALTER is surfaced
        # later as a normal query error rather than a crash loop here.
        import logging
        logging.getLogger("cfddns.db").warning("column migration skipped", exc_info=True)


def get_session() -> Session:
    return Session(engine)


@contextmanager
def session_scope():
    sess = get_session()
    try:
        yield sess
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()
