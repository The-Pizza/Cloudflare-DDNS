"""Shared pytest fixtures.

Critical: environment variables MUST be set before `core.config` is imported,
because `settings = Settings()` reads the environment at import time. We point
the app at a throwaway temp SQLite DB and disable legacy import so tests never
touch a real database or the network.
"""
import os
import tempfile

# --- set env BEFORE importing any core.* module ---------------------------
_TMP_DB_FD, _TMP_DB_PATH = tempfile.mkstemp(suffix=".db", prefix="cfddns-test-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP_DB_PATH}")
os.environ.setdefault("CF_API_TOKEN", "test-token")
os.environ.setdefault("CONFIG_PATH", "/tmp/cfddns-nonexistent.json")
os.environ.setdefault("IMPORT_LEGACY_CONFIG", "false")
os.environ.setdefault("IPV4_ENDPOINT", "https://ipv4.example.test/ip")
# IPv6 disabled by default; individual tests enable it via monkeypatch.
os.environ.setdefault("IPV6_ENDPOINT", "")

import pytest  # noqa: E402

from core.database import engine, init_db  # noqa: E402
from sqlmodel import SQLModel  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    """Recreate all tables before each test for isolation."""
    SQLModel.metadata.drop_all(engine)
    init_db()
    yield
    SQLModel.metadata.drop_all(engine)


@pytest.fixture
def db_session():
    from core.database import get_session
    sess = get_session()
    try:
        yield sess
    finally:
        sess.close()
