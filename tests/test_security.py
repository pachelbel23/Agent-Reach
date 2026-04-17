# -*- coding: utf-8 -*-
"""Security tests for Agent Reach."""

import os
import stat
import sys
from pathlib import Path
import pytest
from agent_reach.config import Config

@pytest.fixture
def tmp_config_dir(tmp_path):
    """Return a temporary config directory."""
    return tmp_path / ".agent-reach"

class TestSecurity:
    def test_to_dict_masks_platform_identifiers(self, tmp_config_dir):
        """Verify that platform-specific identifiers are masked."""
        config_file = tmp_config_dir / "config.yaml"
        config = Config(config_path=config_file)

        # Test various sensitive keys used by platforms
        sensitive_data = {
            "twitter_auth_token": "secret_token_1234567890",
            "twitter_ct0": "secret_ct0_1234567890",
            "bilibili_sessdata": "secret_sessdata_1234567890",
            "bilibili_csrf": "secret_csrf_1234567890",
            "xhs_cookie": "secret_cookie_1234567890",
            "github_token": "secret_github_1234567890",
            "jct_value": "secret_jct_1234567890",
            "auth_key": "secret_auth_1234567890",
        }

        for k, v in sensitive_data.items():
            config.set(k, v)

        masked = config.to_dict()

        for k in sensitive_data:
            # Check if masked (showing only first 8 chars + ...)
            assert masked[k].endswith("...")
            assert len(masked[k]) == 11
            assert "secret" not in masked[k][8:]

    def test_config_dir_permissions(self, tmp_config_dir):
        """Verify that the config directory has restricted permissions."""
        if sys.platform == "win32":
            pytest.skip("Permission checks not applicable on Windows")

        config_file = tmp_config_dir / "config.yaml"
        # Initializing Config should create the directory via _ensure_dir
        config = Config(config_path=config_file)

        mode = tmp_config_dir.stat().st_mode
        # Directory should be 0o700 (drwx------)
        assert stat.S_IMODE(mode) == 0o700
        assert not (mode & stat.S_IRGRP), "group read should not be set"
        assert not (mode & stat.S_IWGRP), "group write should not be set"
        assert not (mode & stat.S_IXGRP), "group execute should not be set"
        assert not (mode & stat.S_IROTH), "other read should not be set"
        assert not (mode & stat.S_IWOTH), "other write should not be set"
        assert not (mode & stat.S_IXOTH), "other execute should not be set"
