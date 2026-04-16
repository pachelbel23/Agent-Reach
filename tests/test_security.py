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
    """Create a temporary config directory."""
    return tmp_path / ".agent-reach"


class TestSecurity:
    def test_masking_platform_identifiers(self, tmp_config_dir):
        """Test that platform-specific identifiers are masked in to_dict()."""
        config_file = tmp_config_dir / "config.yaml"
        config = Config(config_path=config_file)

        # Sensitive values
        config.set("twitter_auth_token", "secret_auth_token_123456789")
        config.set("twitter_ct0", "secret_ct0_123456789")
        config.set("bilibili_sessdata", "secret_sessdata_123456789")
        config.set("bilibili_csrf", "secret_csrf_123456789")
        config.set("bili_jct", "secret_jct_123456789")
        config.set("xhs_cookie", "secret_cookie_123456789")

        masked = config.to_dict()

        # Check masking (currently some might fail before fix)
        assert masked["twitter_auth_token"] == "secret_a..."
        # The following are expected to FAIL before the fix
        assert masked["twitter_ct0"] == "secret_c..."
        assert masked["bilibili_sessdata"] == "secret_s..."
        assert masked["bilibili_csrf"] == "secret_c..."
        assert masked["bili_jct"] == "secret_j..."
        assert masked["xhs_cookie"] == "secret_c..."

    def test_directory_permissions(self, tmp_config_dir):
        """Test that the config directory has restricted permissions (0o700)."""
        if sys.platform == "win32":
            pytest.skip("Permissions test not applicable on Windows")

        config_file = tmp_config_dir / "config.yaml"
        # Config constructor calls _ensure_dir
        Config(config_path=config_file)

        mode = os.stat(tmp_config_dir).st_mode
        # Expected 0o700 (drwx------)
        assert stat.S_IMODE(mode) == 0o700

    def test_file_permissions_on_overwrite(self, tmp_config_dir):
        """Test that config file permissions are corrected on overwrite."""
        if sys.platform == "win32":
            pytest.skip("Permissions test not applicable on Windows")

        config_file = tmp_config_dir / "config.yaml"
        tmp_config_dir.mkdir(parents=True, exist_ok=True)

        # Create file with loose permissions
        config_file.touch()
        os.chmod(config_file, 0o644)
        assert stat.S_IMODE(os.stat(config_file).st_mode) == 0o644

        config = Config(config_path=config_file)
        config.set("key", "value") # Triggers save()

        mode = os.stat(config_file).st_mode
        # Expected 0o600 (-rw-------)
        assert stat.S_IMODE(mode) == 0o600
