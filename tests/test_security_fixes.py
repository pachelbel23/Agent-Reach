# -*- coding: utf-8 -*-
"""Security tests for Agent Reach."""

import os
import stat
import sys
from pathlib import Path
import pytest
from agent_reach.config import Config

@pytest.fixture
def tmp_secure_dir(tmp_path):
    """Temporary directory for security tests."""
    return tmp_path / ".agent-reach"

def test_sensitive_masking_complete(tmp_path):
    """Verify all platform-specific sensitive identifiers are masked."""
    config_path = tmp_path / "test_masking.yaml"
    config = Config(config_path=config_path)
    config.data = {
        "twitter_ct0": "secret_ct0_value_long_enough",
        "xhs_cookie": "secret_xhs_cookie_long_enough",
        "bilibili_sessdata": "secret_sessdata_long_enough",
        "bili_jct": "secret_jct_long_enough",
        "github_token": "secret_token_long_enough",
        "normal_setting": "normal_value"
    }
    masked = config.to_dict()

    assert masked["twitter_ct0"] == "secret_c..."
    assert masked["xhs_cookie"] == "secret_x..."
    assert masked["bilibili_sessdata"] == "secret_s..."
    assert masked["bili_jct"] == "secret_j..."
    assert masked["github_token"] == "secret_t..."
    assert masked["normal_setting"] == "normal_value"

@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
def test_dir_permissions_restricted(tmp_secure_dir):
    """Verify config directory is created with 0o700 permissions."""
    config_path = tmp_secure_dir / "config.yaml"
    Config(config_path=config_path)

    mode = tmp_secure_dir.stat().st_mode
    assert stat.S_IMODE(mode) == 0o700

@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
def test_file_permissions_enforced_on_save(tmp_secure_dir):
    """Verify config file permission 0o600 is enforced even if file pre-existed with broad perms."""
    config_path = tmp_secure_dir / "config.yaml"

    # Pre-create directory and file with broad permissions
    tmp_secure_dir.mkdir(parents=True, exist_ok=True)
    config_path.write_text("key: old_value")
    os.chmod(config_path, 0o644)

    config = Config(config_path=config_path)
    config.set("key", "new_value")

    mode = config_path.stat().st_mode
    assert stat.S_IMODE(mode) == 0o600
