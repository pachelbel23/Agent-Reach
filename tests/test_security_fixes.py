# -*- coding: utf-8 -*-
"""Regression tests for Sentinel security fixes and enhancements."""

import json
import os
import sys

import pytest

from agent_reach.config import Config
from agent_reach.cookie_extract import _sync_xfetch_session


def test_sensitive_masking(tmp_path):
    """Test that all sensitive keys are comprehensively masked correctly."""
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    # Test short secret masking (fixed **** string)
    config.set("twitter_ct0", "abc")
    masked = config.to_dict()
    assert masked["twitter_ct0"] == "****"

    # Test long secret masking (first 8 characters + ...)
    config.set("exa_api_key", "super-secret-key-12345")
    masked = config.to_dict()
    assert masked["exa_api_key"] == "super-se..."

    # Test falsy non-sensitive preservation
    config.set("some_plain_field", False)
    config.set("another_plain_field", "")
    masked = config.to_dict()
    assert masked["some_plain_field"] is False
    assert masked["another_plain_field"] == ""


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """Test that Config.save() correctly restricts permissions on existing file."""
    if sys.platform == "win32":
        pytest.skip("Permission checks are Unix-only")

    config_file = tmp_path / "config.yaml"
    # Create with loose permissions first
    config_file.touch()
    os.chmod(config_file, 0o666)

    config = Config(config_path=config_file)
    config.set("secret_key", "my-secret")

    mode = config_file.stat().st_mode
    assert (mode & 0o777) == 0o600


def test_sync_xfetch_session_creates_secure_file(tmp_path, monkeypatch):
    """Test that _sync_xfetch_session enforces proper directory and file permissions."""
    if sys.platform == "win32":
        pytest.skip("Permission checks are Unix-only")

    # Mock expanduser to point to tmp_path
    monkeypatch.setattr(os.path, "expanduser", lambda path: str(tmp_path) if path == "~" else path)

    _sync_xfetch_session("test_token", "test_ct0")

    xfetch_dir = tmp_path / ".config" / "xfetch"
    session_file = xfetch_dir / "session.json"

    assert xfetch_dir.exists()
    assert (xfetch_dir.stat().st_mode & 0o777) == 0o700

    assert session_file.exists()
    assert (session_file.stat().st_mode & 0o777) == 0o600

    with open(session_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["authToken"] == "test_token"
    assert data["ct0"] == "test_ct0"


def test_config_permissions(tmp_path):
    """Test that Config class correctly enforces directory and file permissions on instantiation."""
    if sys.platform == "win32":
        pytest.skip("Permission checks are Unix-only")

    config_dir = tmp_path / "my_config_dir"
    config_file = config_dir / "config.yaml"

    config = Config(config_path=config_file)
    config.set("secret_key", "value")

    assert config_dir.exists()
    assert (config_dir.stat().st_mode & 0o777) == 0o700
    assert config_file.exists()
    assert (config_file.stat().st_mode & 0o777) == 0o600
