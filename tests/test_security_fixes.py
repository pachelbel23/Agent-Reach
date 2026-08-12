# -*- coding: utf-8 -*-
"""Regression and unit tests for Sentinel security fixes."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

from agent_reach.config import Config
from agent_reach.cookie_extract import _sync_xfetch_session
from agent_reach.doctor import check_all, format_report


def test_sensitive_masking():
    """Verify that sensitive values in Config are properly masked in to_dict."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.yaml"
        config = Config(config_path=config_path)

        # Longer secrets
        config.set("exa_api_key", "super-secret-key-12345")
        config.set("twitter_ct0", "abcdefghijklmnopqrstuvwxyz")
        config.set("bilibili_sessdata", "1234567890abcdef")
        config.set("some_csrf_token", "csrf-token-string")
        config.set("secure_cookie_val", "cookie-data-info-more")
        config.set("bili_jct", "jct-token-goes-here")
        config.set("normal_val", "not-sensitive")

        # Shorter secrets
        config.set("short_key", "secret")
        config.set("short_token", "tok")

        masked = config.to_dict()

        assert masked["exa_api_key"] == "super-se..."
        assert masked["twitter_ct0"] == "abcdefgh..."
        assert masked["bilibili_sessdata"] == "12345678..."
        assert masked["some_csrf_token"] == "csrf-tok..."
        assert masked["secure_cookie_val"] == "cookie-d..."
        assert masked["bili_jct"] == "jct-toke..."
        assert masked["normal_val"] == "not-sensitive"

        # Short secrets masked with fixed "****"
        assert masked["short_key"] == "****"
        assert masked["short_token"] == "****"


def test_config_permissions():
    """Verify that Config enforces restricted file and directory permissions."""
    if sys.platform == "win32":
        pytest.skip("File permission checks not supported on Windows")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Pre-create the file with overly relaxed permissions (e.g. 0o666)
        config_dir = Path(tmpdir) / ".agent-reach"
        config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(config_dir, 0o777)

        config_file = config_dir / "config.yaml"
        with open(config_file, "w") as f:
            f.write("foo: bar")
        os.chmod(config_file, 0o666)

        # Instantiate Config; it should trigger _ensure_dir and load/save
        config = Config(config_path=config_file)
        config.set("secret_key", "12345")

        # Check directory permissions (should be 0o700, i.e., owner only read/write/execute)
        dir_mode = config_dir.stat().st_mode
        assert (dir_mode & 0o777) == 0o700

        # Check file permissions (should be 0o600, i.e., owner only read/write)
        file_mode = config_file.stat().st_mode
        assert (file_mode & 0o777) == 0o600


def test_sync_xfetch_session_creates_secure_file():
    """Verify that _sync_xfetch_session enforces restrictive permissions on target directories and files."""
    if sys.platform == "win32":
        pytest.skip("File permission checks not supported on Windows")

    # Mock the home directory to use a temporary directory
    with tempfile.TemporaryDirectory() as tmpdir:
        original_home = os.environ.get("HOME")
        os.environ["HOME"] = tmpdir
        try:
            # First sync (file doesn't exist)
            _sync_xfetch_session("my-auth-token", "my-ct0")

            xfetch_dir = Path(tmpdir) / ".config" / "xfetch"
            session_file = xfetch_dir / "session.json"

            assert xfetch_dir.exists()
            assert session_file.exists()

            # Verify permissions
            dir_mode = xfetch_dir.stat().st_mode
            assert (dir_mode & 0o777) == 0o700

            file_mode = session_file.stat().st_mode
            assert (file_mode & 0o777) == 0o600

            # Overwrite file with looser permissions and sync again to test existing file correction
            os.chmod(session_file, 0o666)
            _sync_xfetch_session("new-token", "new-ct0")

            file_mode_after = session_file.stat().st_mode
            assert (file_mode_after & 0o777) == 0o600

        finally:
            if original_home is not None:
                os.environ["HOME"] = original_home
            else:
                os.environ.pop("HOME", None)


def test_doctor_reports_permission_issues():
    """Test that agent-reach doctor reports security warnings if config or directory permissions are too wide."""
    if sys.platform == "win32":
        pytest.skip("File permission checks not supported on Windows")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Save original Config CONFIG_DIR and point to tmpdir
        original_config_dir = Config.CONFIG_DIR
        try:
            Config.CONFIG_DIR = Path(tmpdir) / ".agent-reach"
            Config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

            config_file = Config.CONFIG_DIR / "config.yaml"
            config = Config(config_path=config_file)
            config.set("foo", "bar")

            # Force overly loose permissions
            os.chmod(Config.CONFIG_DIR, 0o755)
            os.chmod(config_file, 0o644)

            # Check doctor formatting
            results = check_all(config)
            report = format_report(results)

            assert "安全提示：配置目录 ~/.agent-reach 权限过宽" in report
            assert "安全提示：config.yaml 权限过宽" in report

        finally:
            Config.CONFIG_DIR = original_config_dir
