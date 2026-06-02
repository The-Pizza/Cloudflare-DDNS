"""Tests for config helpers: annotation key parsing + effective-value logic."""
import pytest

from core import config
from core.config import annotation_keys, get_effective
from core.database import get_session
from core.models import Setting


def test_annotation_keys_single(monkeypatch):
    monkeypatch.setattr(config.settings, "annotation_key", "cloudflare-ddns.io/dns-name")
    # env-locked path returns the settings value directly
    monkeypatch.setattr(config, "env_locked", lambda: {"annotation_key"})
    assert annotation_keys() == ["cloudflare-ddns.io/dns-name"]


def test_annotation_keys_comma_list_and_whitespace(monkeypatch):
    monkeypatch.setattr(config.settings, "annotation_key",
                        "cloudflare-ddns.io/dns-name, old.example/dns , , ")
    monkeypatch.setattr(config, "env_locked", lambda: {"annotation_key"})
    assert annotation_keys() == ["cloudflare-ddns.io/dns-name", "old.example/dns"]


def test_get_effective_db_overrides_default(monkeypatch):
    # No env lock → DB value should win over the dataclass default
    monkeypatch.setattr(config, "env_locked", lambda: set())
    sess = get_session()
    try:
        sess.add(Setting(key="annotation_key", value="custom.io/key"))
        sess.commit()
    finally:
        sess.close()
    assert get_effective("annotation_key") == "custom.io/key"


def test_get_effective_env_lock_beats_db(monkeypatch):
    # When env-locked, the settings value wins regardless of DB
    monkeypatch.setattr(config.settings, "annotation_key", "env.io/key")
    monkeypatch.setattr(config, "env_locked", lambda: {"annotation_key"})
    sess = get_session()
    try:
        sess.add(Setting(key="annotation_key", value="db.io/key"))
        sess.commit()
    finally:
        sess.close()
    assert get_effective("annotation_key") == "env.io/key"


def test_get_effective_bool_coercion(monkeypatch):
    monkeypatch.setattr(config, "env_locked", lambda: set())
    sess = get_session()
    try:
        sess.add(Setting(key="session_cookie_secure", value="false"))
        sess.commit()
    finally:
        sess.close()
    assert get_effective("session_cookie_secure") is False


def test_get_effective_int_coercion(monkeypatch):
    monkeypatch.setattr(config, "env_locked", lambda: set())
    sess = get_session()
    try:
        sess.add(Setting(key="poll_interval_seconds", value="120"))
        sess.commit()
    finally:
        sess.close()
    assert get_effective("poll_interval_seconds") == 120
