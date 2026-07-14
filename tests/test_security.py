# -*- coding: utf-8 -*-
"""Security-related tests for Agent Reach."""

import os
import stat
import sys
from pathlib import Path

import pytest
from agent_reach.config import Config


class TestSecurity:
    def test_to_dict_masks_platform_specific_secrets(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config = Config(config_path=config_file)

        # Test Twitter secrets
        config.set("twitter_ct0", "secret_ct0_value_123456")
        # Test Bilibili secrets
        config.set("bilibili_sessdata", "secret_sessdata_value_123456")
        config.set("bilibili_jct", "secret_jct_value_123456")
        # Test generic cookies
        config.set("xhs_cookie", "secret_cookie_value_123456")

        masked = config.to_dict()

        assert masked["twitter_ct0"] == "secret_c..."
        assert masked["bilibili_sessdata"] == "secret_s..."
        assert masked["bilibili_jct"] == "secret_j..."
        assert masked["xhs_cookie"] == "secret_c..."

    def test_to_dict_masks_short_secrets(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config = Config(config_path=config_file)

        config.set("short_key", "123")
        config.set("short_token", "abc")

        masked = config.to_dict()

        assert masked["short_key"] == "****"
        assert masked["short_token"] == "****"

    def test_save_enforces_permissions_on_existing_file(self, tmp_path):
        if sys.platform == "win32":
            pytest.skip("Permission enforcement tests only for Unix-like systems")

        config_file = tmp_path / "config.yaml"
        # Create file with broad permissions
        with open(config_file, "w") as f:
            f.write("{}")
        os.chmod(config_file, 0o644)
        assert (config_file.stat().st_mode & 0o777) == 0o644

        config = Config(config_path=config_file)
        config.set("any_key", "value") # Triggers save()

        assert (config_file.stat().st_mode & 0o777) == 0o600

    def test_config_directory_permissions(self, tmp_path, monkeypatch):
        if sys.platform == "win32":
            pytest.skip("Permission enforcement tests only for Unix-like systems")

        # We need to make sure Config uses our tmp_path as base for its default if we don't pass it
        # But here we pass config_path, so it uses that.
        # Let's test directory creation and permission enforcement.
        config_dir = tmp_path / "secure_dir"
        config_dir.mkdir()
        os.chmod(config_dir, 0o755)
        assert (config_dir.stat().st_mode & 0o777) == 0o755

        config_file = config_dir / "config.yaml"
        config = Config(config_path=config_file)

        assert (config_dir.stat().st_mode & 0o777) == 0o700
