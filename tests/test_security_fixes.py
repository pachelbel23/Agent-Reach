# -*- coding: utf-8 -*-
"""Regression and security tests for Agent Reach."""

import os
import stat
import sys
from pathlib import Path

import pytest
import yaml

from agent_reach.config import Config


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """Verify that Config.save() restricts permissions on an already existing file."""
    config_file = tmp_path / "config.yaml"

    # 1. Create file with broad permissions (e.g., 0o644)
    with open(config_file, "w", encoding="utf-8") as f:
        f.write("existing: data")

    if os.name != "nt":
        os.chmod(config_file, 0o644)

    # 2. Instantiate Config and save new data
    config = Config(config_path=config_file)
    config.set("secret_key", "secret-value")

    if os.name != "nt":
        mode = config_file.stat().st_mode
        # Should be restricted to 0o600 (S_IRUSR | S_IWUSR)
        assert (mode & 0o777) == 0o600


def test_sensitive_masking(tmp_path):
    """Verify masking logic in Config.to_dict()."""
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    # Truthy sensitive values >= 8 characters
    config.set("twitter_ct0", "abcdefgh1234")
    config.set("bilibili_sessdata", "sessdata_secret_string")
    config.set("bilibili_jct", "jct_secret_string")
    config.set("my_csrf_token", "csrf_secret_string")
    config.set("custom_cookie", "cookie_secret_string")

    # Truthy sensitive values < 8 characters
    config.set("twitter_auth_token", "short")
    config.set("normal_key", "key")  # Contains key as substring, < 8 chars
    config.set("my_password", "abc")  # Contains password as substring, < 8 chars

    # Falsy sensitive values
    config.set("some_token", "")
    config.set("some_password", None)

    # Falsy non-sensitive values (using keys devoid of any sensitive keywords like 'key', 'token', etc.)
    config.set("devoid_of_sensit_empty_string", "")
    config.set("devoid_of_sensit_false", False)
    config.set("devoid_of_sensit_none", None)

    # Transparent/non-sensitive keys (using strings devoid of any sensitive keywords)
    config.set("transparent_setting", "visible_setting")
    config.set("devoid_val", "another_one")

    masked = config.to_dict()

    # Verify truthy >= 8 characters are masked with first 8 characters and ellipsis
    assert masked["twitter_ct0"] == "abcdefgh..."
    assert masked["bilibili_sessdata"] == "sessdata..."
    assert masked["bilibili_jct"] == "jct_secr..."
    assert masked["my_csrf_token"] == "csrf_sec..."
    assert masked["custom_cookie"] == "cookie_s..."

    # Verify truthy < 8 characters are masked with ****
    assert masked["twitter_auth_token"] == "****"
    assert masked["normal_key"] == "****"
    assert masked["my_password"] == "****"

    # Verify falsy sensitive values are masked as None
    assert masked["some_token"] is None
    assert masked["some_password"] is None

    # Verify falsy non-sensitive values are preserved exactly
    assert masked["devoid_of_sensit_empty_string"] == ""
    assert masked["devoid_of_sensit_false"] is False
    assert masked["devoid_of_sensit_none"] is None

    # Verify transparent keys are preserved exactly
    assert masked["transparent_setting"] == "visible_setting"
    assert masked["devoid_val"] == "another_one"


def test_config_permissions(tmp_path):
    """Verify permission enforcement is only verified when targeting the intended configuration directory."""
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    if os.name != "nt":
        # Check that the directory got created with 0o700 permissions
        mode = config_file.parent.stat().st_mode
        assert (mode & 0o777) == 0o700


def test_load_fallback_safeguard(tmp_path):
    """Verify load() robustly handles malformed/non-dictionary YAML content."""
    config_file = tmp_path / "config.yaml"

    # Write non-dictionary data (like a string or a list) to YAML file
    with open(config_file, "w", encoding="utf-8") as f:
        yaml.safe_dump("non-dictionary-string-content", f)

    config = Config(config_path=config_file)
    assert isinstance(config.data, dict)
    assert config.data == {}


def test_sync_xfetch_session_creates_secure_file(tmp_path, monkeypatch):
    """Verify that _sync_xfetch_session creates xfetch files and directories securely."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    # Mock home directory expanduser
    monkeypatch.setattr(os.path, "expanduser", lambda path: str(fake_home) if path == "~" else path)

    from agent_reach.cookie_extract import _sync_xfetch_session
    _sync_xfetch_session("fake_token", "fake_ct0")

    session_file = fake_home / ".config" / "xfetch" / "session.json"
    assert session_file.exists()

    if os.name != "nt":
        # Check directory permission (0o700)
        dir_mode = session_file.parent.stat().st_mode
        assert (dir_mode & 0o777) == 0o700
        # Check file permission (0o600)
        file_mode = session_file.stat().st_mode
        assert (file_mode & 0o777) == 0o600
