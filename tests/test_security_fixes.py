# -*- coding: utf-8 -*-
"""Regression and security tests for Agent Reach configuration and cookie sync."""

import json
import os
import sys

import pytest

from agent_reach.config import Config
from agent_reach.cookie_extract import _sync_xfetch_session


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Temporary directory for security testing."""
    return tmp_path


def test_sensitive_masking(tmp_config_dir):
    """Verify Config.to_dict() masks all sensitive keywords and short secrets securely."""
    config_file = tmp_config_dir / "config.yaml"
    config = Config(config_path=config_file)

    # Test long sensitive keys (should show first 8 chars and ...)
    config.set("exa_api_key", "super-secret-key-12345")
    config.set("github_token", "github_token_abcdefg_98765")
    config.set("twitter_ct0", "ct0_value_abcdefg")
    config.set("bilibili_sessdata", "sessdata_value_abcdefg")
    config.set("bilibili_csrf", "csrf_value_abcdefg")
    config.set("xhs_cookie", "cookie_value_abcdefg")
    config.set("bili_jct", "jct_value_abcdefg")

    # Test short sensitive keys (should mask to ****)
    config.set("short_key", "123")
    config.set("short_password", "abcde")

    # Test transparent non-sensitive keys (should not be masked)
    config.set("normal_setting", "visible_setting")
    config.set("theme", "dark")

    # Test falsy non-sensitive / non-none values
    config.set("some_cookie_flag", False)
    config.set("empty_token", "")
    config.set("none_key", None)

    masked = config.to_dict()

    # Assert long keys are masked to 8 characters + ...
    assert masked["exa_api_key"] == "super-se..."
    assert masked["github_token"] == "github_t..."
    assert masked["twitter_ct0"] == "ct0_valu..."
    assert masked["bilibili_sessdata"] == "sessdata..."
    assert masked["bilibili_csrf"] == "csrf_val..."
    assert masked["xhs_cookie"] == "cookie_v..."
    assert masked["bili_jct"] == "jct_valu..."

    # Assert short keys are masked to ****
    assert masked["short_key"] == "****"
    assert masked["short_password"] == "****"

    # Assert non-sensitive keys are untouched
    assert masked["normal_setting"] == "visible_setting"
    assert masked["theme"] == "dark"

    # Assert falsy non-none values are preserved
    assert masked["some_cookie_flag"] is False
    assert masked["empty_token"] == ""
    assert masked["none_key"] is None


def test_save_enforces_permissions_on_existing_file(tmp_config_dir):
    """Verify Config.save() restricts permissions of an existing file with broader access."""
    if sys.platform == "win32":
        pytest.skip("Permission checks are not applicable on Windows.")

    config_file = tmp_config_dir / "secure_config.yaml"

    # Pre-create file with broad permissions (e.g., 0o644)
    with open(config_file, "w", encoding="utf-8") as f:
        f.write("{}")
    os.chmod(config_file, 0o644)

    # Confirm broad permissions are set
    initial_mode = config_file.stat().st_mode & 0o777
    assert initial_mode == 0o644

    # Save via Config
    config = Config(config_path=config_file)
    config.set("some_key", "value")

    # Verify permissions are restricted to 0o600
    final_mode = config_file.stat().st_mode & 0o777
    assert final_mode == 0o600


def test_config_permissions(tmp_config_dir):
    """Verify directory permissions are enforced on Config initialization on non-Windows platforms."""
    if sys.platform == "win32":
        pytest.skip("Permission checks are not applicable on Windows.")

    config_dir = tmp_config_dir / "test_app_dir"
    config_file = config_dir / "config.yaml"

    # Directory doesn't exist yet, config should create it with 0o700
    config = Config(config_path=config_file)
    config.save()

    dir_mode = config_dir.stat().st_mode & 0o777
    assert dir_mode == 0o700

    file_mode = config_file.stat().st_mode & 0o777
    assert file_mode == 0o600


def test_sync_xfetch_session_creates_secure_file(monkeypatch, tmp_path):
    """Verify that _sync_xfetch_session enforces proper permissions on both directory and session file."""
    # Mock user home directory
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(os.path, "expanduser", lambda path: str(tmp_path) if path == "~" else path)

    _sync_xfetch_session("test_auth_token_123", "test_ct0_456")

    xfetch_dir = tmp_path / ".config" / "xfetch"
    session_file = xfetch_dir / "session.json"

    assert xfetch_dir.exists()
    assert session_file.exists()

    with open(session_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["authToken"] == "test_auth_token_123"
        assert data["ct0"] == "test_ct0_456"

    if sys.platform != "win32":
        dir_mode = xfetch_dir.stat().st_mode & 0o777
        assert dir_mode == 0o700

        file_mode = session_file.stat().st_mode & 0o777
        assert file_mode == 0o600
