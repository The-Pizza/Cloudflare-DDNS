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
