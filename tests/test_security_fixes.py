# -*- coding: utf-8 -*-
"""Regression and security tests."""

import json
import os

from agent_reach.config import Config
from agent_reach.cookie_extract import _sync_xfetch_session


def test_sync_xfetch_session_creates_secure_file(tmp_path, monkeypatch):
    """
    Validates that _sync_xfetch_session enforces 0o700 permissions on the
    ~/.config/xfetch directory and 0o600 permissions on the created session.json file.
    """
    # Mock expanduser to use our temp path instead of actual home directory
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(os.path, "expanduser", lambda path: str(fake_home) if path == "~" else path)

    _sync_xfetch_session("test_auth_token", "test_ct0")

    xfetch_dir = fake_home / ".config" / "xfetch"
    session_file = xfetch_dir / "session.json"

    assert xfetch_dir.exists()
    assert session_file.exists()

    with open(session_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["authToken"] == "test_auth_token"
        assert data["ct0"] == "test_ct0"

    if os.name != "nt":
        # Check xfetch_dir permissions
        dir_mode = xfetch_dir.stat().st_mode & 0o777
        assert dir_mode == 0o700

        # Check session_file permissions
        file_mode = session_file.stat().st_mode & 0o777
        assert file_mode == 0o600


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """
    Verifies that Config.save() correctly restricts file permissions to 0o600
    even if the file already exists with broader access.
    """
    config_file = tmp_path / "config.yaml"

    # Pre-create file with broad permissions (e.g., 0o644)
    with open(config_file, "w") as f:
        f.write("existing: data")

    if os.name != "nt":
        os.chmod(config_file, 0o644)
        assert (config_file.stat().st_mode & 0o777) == 0o644

    config = Config(config_path=config_file)
    config.set("new_key", "secured_value")

    if os.name != "nt":
        file_mode = config_file.stat().st_mode & 0o777
        assert file_mode == 0o600


def test_sensitive_masking(tmp_path):
    """
    Ensures that sensitive identifiers like ct0, sessdata, and jct
    are permanently masked in configuration outputs.
    """
    config = Config(config_path=tmp_path / "config.yaml")

    # Long secrets (>= 8 characters)
    config.set("twitter_ct0", "long_secret_ct0_value")
    config.set("bilibili_sessdata", "sessdata_super_secret_value")
    config.set("bilibili_csrf", "csrf_jct_token_here")
    config.set("other_jct", "jct_token_here")
    config.set("normal_setting", "perfectly_visible")

    # Short secrets (< 8 characters)
    config.set("short_key", "abc")
    config.set("short_token", "123")

    masked = config.to_dict()

    assert masked["twitter_ct0"] == "long_sec..."
    assert masked["bilibili_sessdata"] == "sessdata..."
    assert masked["bilibili_csrf"] == "csrf_jct..."
    assert masked["other_jct"] == "jct_toke..."
    assert masked["normal_setting"] == "perfectly_visible"

    assert masked["short_key"] == "****"
    assert masked["short_token"] == "****"


def test_config_permissions(tmp_path):
    """
    Verifies permission enforcement is only verified when targeting
    the intended application configuration directory.
    """
    # Check that creating config in any path correctly sets directory permissions to 0o700 on Unix
    config_file = tmp_path / "custom_app_dir" / "config.yaml"
    _ = Config(config_path=config_file)

    if os.name != "nt":
        dir_mode = config_file.parent.stat().st_mode & 0o777
        assert dir_mode == 0o700
