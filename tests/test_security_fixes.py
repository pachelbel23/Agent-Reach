# -*- coding: utf-8 -*-
"""Regression and security tests for Agent Reach security enhancements."""

import os
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
import yaml

from agent_reach.config import Config
from agent_reach.cookie_extract import _sync_xfetch_session


def test_config_permissions(tmp_path):
    """Verify that config files and directories enforce secure permissions on Unix-like systems."""
    if sys.platform == "win32":
        pytest.skip("Permission checks are non-Windows (Unix) only")

    config_dir = tmp_path / "secure_config_dir"
    config_file = config_dir / "config.yaml"

    # 1. Directory creation permissions (0o700)
    config = Config(config_path=config_file)
    assert config_dir.exists()
    dir_mode = config_dir.stat().st_mode & 0o777
    assert dir_mode == 0o700, f"Directory mode is {oct(dir_mode)}, expected 0o700"

    # 2. File creation permissions (0o600)
    config.set("foo", "bar")
    file_mode = config_file.stat().st_mode & 0o777
    assert file_mode == 0o600, f"File mode is {oct(file_mode)}, expected 0o600"


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """Verify Config.save() correctly restricts file permissions even if the file already exists with broader access."""
    if sys.platform == "win32":
        pytest.skip("Permission checks are non-Windows (Unix) only")

    config_file = tmp_path / "existing_broad_perms.yaml"

    # Create file with broad permissions (0o666 or similar)
    config_file.touch()
    os.chmod(config_file, 0o666)
    initial_mode = config_file.stat().st_mode & 0o777
    assert initial_mode == 0o666, "Initial broad permissions should be set"

    config = Config(config_path=config_file)
    config.set("secret", "value")

    final_mode = config_file.stat().st_mode & 0o777
    assert final_mode == 0o600, f"File mode did not secure to 0o600, got {oct(final_mode)}"


def test_sensitive_masking():
    """Verify Config.to_dict() correctly masks sensitive information using expanded keywords and secure formatting."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.yaml"
        config = Config(config_path=config_path)

        # 1. Sensitive keys (>= 8 characters) -> show prefix + '...'
        config.set("twitter_auth_token", "supersecrettokenvalue")
        config.set("bilibili_sessdata", "bili_sess_1234567")
        config.set("twitter_ct0", "ct0_value_98765")
        config.set("bilibili_csrf", "bili_csrf_value")
        config.set("xhs_cookie", "xhs_cookie_value")
        config.set("bili_jct", "bili_jct_value")

        # 2. Sensitive keys (< 8 characters) -> show '****'
        config.set("short_key", "secret")
        config.set("short_token", "tok")

        # 3. Non-sensitive keys -> unchanged
        config.set("visible_setting", "normal")
        config.set("falsy_non_sensitive", False)
        config.set("empty_non_sensitive", "")

        # 4. Falsy sensitive keys -> mapped to None
        config.set("falsy_sensitive_key", "")
        config.set("none_sensitive_token", None)

        masked = config.to_dict()

        # Check masking for long secrets
        assert masked["twitter_auth_token"] == "supersec..."
        assert masked["bilibili_sessdata"] == "bili_ses..."
        assert masked["twitter_ct0"] == "ct0_valu..."
        assert masked["bilibili_csrf"] == "bili_csr..."
        assert masked["xhs_cookie"] == "xhs_cook..."
        assert masked["bili_jct"] == "bili_jct..."

        # Check masking for short secrets (must be fixed-length ****)
        assert masked["short_key"] == "****"
        assert masked["short_token"] == "****"

        # Check non-sensitive values are preserved
        assert masked["visible_setting"] == "normal"
        assert masked["falsy_non_sensitive"] is False
        assert masked["empty_non_sensitive"] == ""

        # Check falsy sensitive values are mapped to None
        assert masked["falsy_sensitive_key"] is None
        assert masked["none_sensitive_token"] is None


def test_load_malformed_config(tmp_path):
    """Verify Config.load() handles non-dictionary structures gracefully."""
    config_file = tmp_path / "malformed.yaml"

    # Write a non-dictionary (list) YAML file
    with open(config_file, "w", encoding="utf-8") as f:
        yaml.dump(["item1", "item2"], f)

    config = Config(config_path=config_file)
    assert isinstance(config.data, dict)
    assert config.data == {}


def test_sync_xfetch_session_permissions(tmp_path):
    """Verify that _sync_xfetch_session creates directories and files with restricted permissions."""
    with patch("os.path.expanduser", return_value=str(tmp_path)):
        _sync_xfetch_session("dummy_auth", "dummy_ct0")

        xfetch_dir = tmp_path / ".config" / "xfetch"
        session_file = xfetch_dir / "session.json"

        assert xfetch_dir.exists()
        assert session_file.exists()

        if sys.platform != "win32":
            dir_mode = xfetch_dir.stat().st_mode & 0o777
            file_mode = session_file.stat().st_mode & 0o777

            assert dir_mode == 0o700, f"Expected xfetch dir to be 0o700, got {oct(dir_mode)}"
            assert file_mode == 0o600, f"Expected session.json file to be 0o600, got {oct(file_mode)}"
