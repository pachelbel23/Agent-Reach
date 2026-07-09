# -*- coding: utf-8 -*-
"""Tests for Agent Reach config module."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from agent_reach.config import Config


@pytest.fixture
def tmp_config(tmp_path):
    """Create a Config with a temporary directory."""
    config_file = tmp_path / "config.yaml"
    return Config(config_path=config_file)


class TestConfig:
    def test_init_creates_dir(self, tmp_path):
        config_file = tmp_path / "subdir" / "config.yaml"
        config = Config(config_path=config_file)
        assert config_file.parent.exists()

    def test_set_and_get(self, tmp_config):
        tmp_config.set("test_key", "test_value")
        assert tmp_config.get("test_key") == "test_value"

    def test_get_default(self, tmp_config):
        assert tmp_config.get("nonexistent") is None
        assert tmp_config.get("nonexistent", "default") == "default"

    def test_get_from_env(self, tmp_config, monkeypatch):
        monkeypatch.setenv("TEST_ENV_KEY", "env_value")
        assert tmp_config.get("test_env_key") == "env_value"

    def test_config_file_priority_over_env(self, tmp_config, monkeypatch):
        monkeypatch.setenv("MY_KEY", "from_env")
        tmp_config.set("my_key", "from_config")
        assert tmp_config.get("my_key") == "from_config"

    def test_save_and_load(self, tmp_config):
        tmp_config.set("key1", "value1")
        tmp_config.set("key2", 42)

        # Create new config from same file
        config2 = Config(config_path=tmp_config.config_path)
        assert config2.get("key1") == "value1"
        assert config2.get("key2") == 42

    def test_delete(self, tmp_config):
        tmp_config.set("to_delete", "value")
        assert tmp_config.get("to_delete") == "value"
        tmp_config.delete("to_delete")
        assert tmp_config.get("to_delete") is None

    def test_is_configured(self, tmp_config):
        assert not tmp_config.is_configured("exa_search")
        tmp_config.set("exa_api_key", "test-key")
        assert tmp_config.is_configured("exa_search")

    def test_is_configured_reddit(self, tmp_config):
        assert not tmp_config.is_configured("reddit_proxy")
        tmp_config.set("reddit_proxy", "http://user:pass@ip:port")
        assert tmp_config.is_configured("reddit_proxy")

    def test_get_configured_features(self, tmp_config):
        features = tmp_config.get_configured_features()
        assert isinstance(features, dict)
        assert "exa_search" in features
        assert all(v is False for v in features.values())

    def test_to_dict_masks_sensitive(self, tmp_config):
        tmp_config.set("exa_api_key", "super-secret-key-12345")
        tmp_config.set("normal_setting", "visible")
        masked = tmp_config.to_dict()
        assert masked["exa_api_key"] == "super-se..."
        assert masked["normal_setting"] == "visible"

    def test_to_dict_masks_platform_specific_secrets(self, tmp_config):
        tmp_config.set("twitter_ct0", "secret_ct0")
        tmp_config.set("bilibili_sessdata", "secret_sessdata")
        tmp_config.set("xhs_cookie", "secret_cookie")
        tmp_config.set("bilibili_jct", "secret_jct")
        tmp_config.set("csrf_token", "secret_csrf")

        masked = tmp_config.to_dict()
        assert masked["twitter_ct0"] == "secret_c..."
        assert masked["bilibili_sessdata"] == "secret_s..."
        assert masked["xhs_cookie"] == "secret_c..."
        assert masked["bilibili_jct"] == "secret_j..."
        assert masked["csrf_token"] == "secret_c..."

    def test_save_creates_file_with_restricted_permissions(self, tmp_path):
        import stat
        import sys
        config_file = tmp_path / "secure_config.yaml"
        config = Config(config_path=config_file)
        config.set("secret_key", "my-secret")

        if sys.platform != "win32":
            mode = config_file.stat().st_mode
            # File should be owner-only read/write (0o600)
            assert (mode & 0o777) == 0o600

    def test_save_enforces_permissions_on_existing_file(self, tmp_path):
        import stat
        import sys
        if sys.platform == "win32":
            pytest.skip("Permission checks not applicable on Windows")

        config_file = tmp_path / "existing_config.yaml"
        # Create file with loose permissions
        config_file.write_text("key: value")
        os.chmod(config_file, 0o644)
        assert (config_file.stat().st_mode & 0o777) == 0o644

        config = Config(config_path=config_file)
        config.set("new_key", "new_value")

        # Permissions should now be restricted to 0o600
        assert (config_file.stat().st_mode & 0o777) == 0o600
