# -*- coding: utf-8 -*-
"""Security tests for Agent Reach."""

import os
import stat
import sys
from pathlib import Path
import pytest
from agent_reach.config import Config

@pytest.fixture
def tmp_config(tmp_path):
    """Create a Config with a temporary directory."""
    config_file = tmp_path / "config.yaml"
    return Config(config_path=config_file)

class TestSecurity:
    def test_masking_platform_specific_identifiers(self, tmp_config):
        """Test that platform-specific identifiers are masked."""
        sensitive_data = {
            "twitter_ct0": "secret_ct0_value",
            "bilibili_sessdata": "secret_sessdata_value",
            "bilibili_csrf": "secret_jct_value",
            "xhs_cookie": "secret_cookie_value",
            "auth_token": "secret_auth_token",
            "bili_jct": "secret_bili_jct",
        }
        for k, v in sensitive_data.items():
            tmp_config.set(k, v)

        masked = tmp_config.to_dict()

        for k in sensitive_data:
            assert masked[k].endswith("..."), f"{k} should be masked"
            assert len(masked[k]) == 11 # 8 chars + '...'

    def test_save_enforces_permissions_on_existing_file(self, tmp_path):
        """Test that save() corrects insecure permissions on existing files."""
        if sys.platform == "win32":
            pytest.skip("File permissions (chmod) not applicable on Windows in this way")

        config_file = tmp_path / "insecure.yaml"
        # Create file with broad permissions
        config_file.write_text("initial: content")
        os.chmod(config_file, 0o644)
        assert (config_file.stat().st_mode & 0o777) == 0o644

        config = Config(config_path=config_file)
        config.set("security", "first")

        # Verify permissions are now restricted
        assert (config_file.stat().st_mode & 0o777) == 0o600

    def test_masking_still_works_for_general_keys(self, tmp_config):
        """Test that original masking for 'key', 'token', 'password', 'proxy' still works."""
        sensitive_data = {
            "exa_api_key": "secret_key",
            "github_token": "secret_token",
            "db_password": "secret_password",
            "reddit_proxy": "secret_proxy",
        }
        for k, v in sensitive_data.items():
            tmp_config.set(k, v)

        masked = tmp_config.to_dict()

        for k in sensitive_data:
            assert masked[k].endswith("..."), f"{k} should be masked"
