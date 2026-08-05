# -*- coding: utf-8 -*-
"""Security regression tests for Agent Reach."""

import os
import stat
import sys
from pathlib import Path

import pytest

from agent_reach.config import Config
from agent_reach.cookie_extract import _sync_xfetch_session


def test_sensitive_masking(tmp_path):
    """Test that Config.to_dict() securely masks sensitive keys while preserving falsy/transparent ones."""
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    # Long sensitive values (8+ chars) -> show first 8 and ...
    config.set("my_api_key", "supersecretkey123456")
    config.set("github_token", "githubtoken789")
    config.set("twitter_ct0", "twitterct0_value")

    # Short sensitive values (<8 chars) -> mask with ****
    config.set("short_password", "pwd")
    config.set("short_csrf", "csrf")

    # Falsy sensitive values -> preserve as is
    config.set("empty_token", "")
    config.set("none_key", None)

    # Transparent keys (completely devoid of sensitive keywords)
    config.set("user_id", "john_doe")
    config.set("is_admin", True)
    config.set("empty_setting", "")
    config.set("false_setting", False)

    masked = config.to_dict()

    # Verify long sensitive masking
    assert masked["my_api_key"] == "supersec..."
    assert masked["github_token"] == "githubto..."
    assert masked["twitter_ct0"] == "twitterc..."

    # Verify short sensitive masking
    assert masked["short_password"] == "****"
    assert masked["short_csrf"] == "****"

    # Verify falsy sensitive values preservation
    assert masked["empty_token"] == ""
    assert masked["none_key"] is None

    # Verify transparent keys preservation (no masking)
    assert masked["user_id"] == "john_doe"
    assert masked["is_admin"] is True
    assert masked["empty_setting"] == ""
    assert masked["false_setting"] is False


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """Verify that Config.save() restricts permissions to 0o600 on existing files."""
    if os.name == "nt":
        pytest.skip("Permission enforcement is not applicable on Windows")

    config_file = tmp_path / "config.yaml"
    # Create the file with broader permissions first (0o644)
    config_file.write_text("{}", encoding="utf-8")
    os.chmod(config_file, 0o644)

    # Verify it has 0o644 permissions initially
    assert (config_file.stat().st_mode & 0o777) == 0o644

    # Load and save via Config
    config = Config(config_path=config_file)
    config.set("some_key", "some_value")  # Calls save()

    # Verify it now has 0o600 permissions
    assert (config_file.stat().st_mode & 0o777) == 0o600


def test_config_permissions(tmp_path):
    """Verify permission enforcement when targeting the config directory on Unix platforms."""
    if os.name == "nt":
        pytest.skip("Permission enforcement is not applicable on Windows")

    config_file = tmp_path / "app_config_dir" / "config.yaml"
    config = Config(config_path=config_file)
    config.set("some_key", "some_value")

    # Check directory permissions (should be 0o700)
    dir_mode = config_file.parent.stat().st_mode & 0o777
    assert dir_mode == 0o700

    # Check file permissions (should be 0o600)
    file_mode = config_file.stat().st_mode & 0o777
    assert file_mode == 0o600


def test_sync_xfetch_session_permissions(tmp_path, monkeypatch):
    """Verify that _sync_xfetch_session creates directories and files with correct permissions."""
    if os.name == "nt":
        pytest.skip("Permission enforcement is not applicable on Windows")

    fake_home = tmp_path / "home"
    fake_home.mkdir()

    # Mock expanduser
    monkeypatch.setattr(os.path, "expanduser", lambda x: str(fake_home) if x == "~" else x)

    _sync_xfetch_session("test_token_val", "test_ct0_val")

    xfetch_dir = fake_home / ".config" / "xfetch"
    session_file = xfetch_dir / "session.json"

    assert xfetch_dir.exists()
    assert session_file.exists()

    # Verify xfetch directory has 0o700 permissions
    assert (xfetch_dir.stat().st_mode & 0o777) == 0o700

    # Verify session file has 0o600 permissions
    assert (session_file.stat().st_mode & 0o777) == 0o600
