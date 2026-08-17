# -*- coding: utf-8 -*-
"""Security regression tests for Agent Reach."""

import json
import os
import stat

from agent_reach.config import Config
from agent_reach.cookie_extract import _sync_xfetch_session
from agent_reach.doctor import format_report


class TestSecurityFixes:
    def test_sync_xfetch_session_creates_secure_file(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setattr(os.path, "expanduser", lambda path: str(fake_home) if path == "~" else path)

        _sync_xfetch_session("test_token_123", "test_ct0_456")

        xfetch_dir = fake_home / ".config" / "xfetch"
        session_path = xfetch_dir / "session.json"

        assert session_path.exists()

        with open(session_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["authToken"] == "test_token_123"
        assert data["ct0"] == "test_ct0_456"

        if os.name != "nt":
            dir_mode = xfetch_dir.stat().st_mode
            file_mode = session_path.stat().st_mode

            assert not (dir_mode & (stat.S_IRWXG | stat.S_IRWXO)), "Directory should be restricted (0o700)"
            assert not (file_mode & (stat.S_IRWXG | stat.S_IRWXO)), "File should be restricted (0o600)"

    def test_sync_xfetch_session_restricts_existing_file_permissions(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setattr(os.path, "expanduser", lambda path: str(fake_home) if path == "~" else path)

        xfetch_dir = fake_home / ".config" / "xfetch"
        xfetch_dir.mkdir(parents=True)
        session_path = xfetch_dir / "session.json"

        # Write initially insecure file
        with open(session_path, "w", encoding="utf-8") as f:
            json.dump({"old": "data"}, f)
        if os.name != "nt":
            os.chmod(session_path, 0o644)

        _sync_xfetch_session("updated_token", "updated_ct0")

        if os.name != "nt":
            file_mode = session_path.stat().st_mode
            assert not (file_mode & (stat.S_IRGRP | stat.S_IROTH)), "Existing file permissions should be restricted to 0o600"

    def test_doctor_report_checks_config_permissions(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config = Config(config_path=config_file)
        config.set("key", "val")

        if os.name != "nt":
            os.chmod(config_file, 0o644)
            report = format_report({"web": {"status": "ok", "name": "网页", "message": "OK", "tier": 0, "backends": []}}, config=config)
            assert "安全提示：config.yaml 权限过宽" in report

            os.chmod(config_file, 0o600)
            report2 = format_report({"web": {"status": "ok", "name": "网页", "message": "OK", "tier": 0, "backends": []}}, config=config)
            assert "安全提示：config.yaml 权限过宽" not in report2
