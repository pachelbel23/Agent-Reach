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
    def test_to_dict_masks_all_sensitive_keywords(self, tmp_config):
        sensitive_data = {
            "exa_api_key": "key-1234567890",
            "twitter_auth_token": "token-1234567890",
            "my_password": "password-1234567890",
            "reddit_proxy": "proxy-1234567890",
            "twitter_ct0": "ct0-1234567890",
            "bilibili_sessdata": "sessdata-1234567890",
            "bilibili_csrf": "csrf-1234567890",
            "xhs_cookie": "cookie-1234567890",
            "auth_header": "auth-1234567890",
            "bili_jct": "jct-1234567890",
        }
        for k, v in sensitive_data.items():
            tmp_config.set(k, v)

        masked = tmp_config.to_dict()
        for k, v in sensitive_data.items():
            assert masked[k] == f"{v[:8]}..."
            assert v not in masked[k]

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions tests")
    def test_config_dir_permissions(self, tmp_path):
        config_dir = tmp_path / "secure_dir"
        config_file = config_dir / "config.yaml"
        # Config init calls _ensure_dir
        Config(config_path=config_file)

        mode = config_dir.stat().st_mode
        assert stat.S_IMODE(mode) == 0o700

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions tests")
    def test_config_file_permissions_on_save(self, tmp_path):
        config_file = tmp_path / "secure_config.yaml"
        # Create file with loose permissions first
        config_file.touch()
        os.chmod(config_file, 0o666)
        assert stat.S_IMODE(config_file.stat().st_mode) == 0o666

        config = Config(config_path=config_file)
        config.set("key", "value") # set() calls save()

        mode = config_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600
