# -*- coding: utf-8 -*-
"""Security and regression tests for Agent Reach."""

import json
import os
import pytest

from agent_reach.cookie_extract import _sync_xfetch_session


def test_sync_xfetch_session_creates_secure_file(tmp_path, monkeypatch):
    """Verify that _sync_xfetch_session creates xfetch files and directories securely."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    # Mock home directory expanduser so that "~" points to fake_home
    monkeypatch.setattr(os.path, "expanduser", lambda path: str(fake_home) if path == "~" else path)

    _sync_xfetch_session("fake_token", "fake_ct0")

    session_file = fake_home / ".config" / "xfetch" / "session.json"
    assert session_file.exists()

    # Verify contents of the session.json
    with open(session_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["authToken"] == "fake_token"
    assert data["ct0"] == "fake_ct0"

    if os.name != "nt":
        # Check directory permission (0o700)
        dir_mode = session_file.parent.stat().st_mode
        assert (dir_mode & 0o777) == 0o700
        # Check file permission (0o600)
        file_mode = session_file.stat().st_mode
        assert (file_mode & 0o777) == 0o600
