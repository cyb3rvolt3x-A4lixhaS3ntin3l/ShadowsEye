"""Smoke tests for sentinel_core Flask app (no live network)."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SENTINEL_CORE = ROOT / "sentinel_core"


@pytest.fixture(scope="module")
def sc_app_module():
    """Import sentinel_core/app.py with cwd/logs set for FileHandler side effects."""
    logs = SENTINEL_CORE / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (SENTINEL_CORE / "db").mkdir(parents=True, exist_ok=True)

    # Ensure sentinel_core is on path as top-level (app.py imports are relative).
    sc = str(SENTINEL_CORE)
    inserted = False
    if sc not in sys.path:
        sys.path.insert(0, sc)
        inserted = True

    prev_cwd = os.getcwd()
    try:
        os.chdir(sc)
        if "app" in sys.modules:
            # Re-import cleanly if another test already loaded a different app.
            mod = importlib.reload(sys.modules["app"])
        else:
            mod = importlib.import_module("app")
        yield mod
    finally:
        os.chdir(prev_cwd)
        # Leave module cached; path entry can stay for subsequent tests.


@pytest.fixture
def client(sc_app_module):
    flask_app = sc_app_module.create_app({"TESTING": True})
    return flask_app.test_client()


def test_create_app_import_and_factory(sc_app_module):
    flask_app = sc_app_module.create_app({"TESTING": True})
    assert flask_app is not None
    assert flask_app.config.get("TESTING") is True
    # Login route registered
    rules = {rule.rule for rule in flask_app.url_map.iter_rules()}
    assert "/login" in rules


def test_bind_host_defaults_to_localhost(sc_app_module, monkeypatch):
    monkeypatch.delenv("SHADOWSEYE_BIND_HOST", raising=False)
    monkeypatch.delenv("SHADOWSEYE_BIND_PORT", raising=False)
    assert sc_app_module.get_bind_host() == "127.0.0.1"
    assert sc_app_module.get_bind_port() == 5001


def test_bind_host_env_override(sc_app_module, monkeypatch):
    monkeypatch.setenv("SHADOWSEYE_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("SHADOWSEYE_BIND_PORT", "8088")
    assert sc_app_module.get_bind_host() == "0.0.0.0"
    assert sc_app_module.get_bind_port() == 8088


def test_login_rejects_empty_password(client, sc_app_module):
    """Empty password must be rejected without authenticating (DB mocked)."""
    mock_query = MagicMock()
    mock_query.filter_by.return_value.first.return_value = MagicMock(
        password_hash="not-used"
    )

    with patch.object(sc_app_module, "User") as MockUser:
        MockUser.query = mock_query
        with patch.object(sc_app_module, "log_audit"):
            resp = client.post(
                "/login",
                data={"username": "admin", "password": ""},
                follow_redirects=False,
            )

    # Stay on login (200) — never redirect to dashboard
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data or b"login" in resp.data.lower()
    # Empty-password path must not hit User.query
    mock_query.filter_by.assert_not_called()


def test_login_rejects_whitespace_password(client, sc_app_module):
    mock_query = MagicMock()
    mock_query.filter_by.return_value.first.return_value = MagicMock()

    with patch.object(sc_app_module, "User") as MockUser:
        MockUser.query = mock_query
        with patch.object(sc_app_module, "log_audit"):
            resp = client.post(
                "/login",
                data={"username": "admin", "password": "   "},
                follow_redirects=False,
            )

    assert resp.status_code == 200
    mock_query.filter_by.assert_not_called()
