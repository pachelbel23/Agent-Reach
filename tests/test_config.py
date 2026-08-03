# -*- coding: utf-8 -*-
"""Tests for Agent Reach config module."""


import pytest

from agent_reach.config import Config


@pytest.fixture
def tmp_config(tmp_path):
    """Create a Config with a temporary directory."""
    config_file = tmp_path / "config.yaml"
    return Config(config_path=config_file)


class TestConfig:
    def test_init_creates_dir(self, tmp_path):
        config_file = tmp_path / "subdir" / "config.yaml"
        _config = Config(config_path=config_file)
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

    def test_save_creates_file_with_restricted_permissions(self, tmp_path):
        import stat
        import sys
        config_file = tmp_path / "secure_config.yaml"
        config = Config(config_path=config_file)
        config.set("secret_key", "my-secret")

        if sys.platform != "win32":
            mode = config_file.stat().st_mode
            # File should be owner-only read/write (0o600)
            assert not (mode & stat.S_IRGRP), "group read should not be set"
            assert not (mode & stat.S_IROTH), "other read should not be set"

    def test_sensitive_masking(self, tmp_config):
        # Long secrets (length >= 8)
        tmp_config.set("twitter_auth_token", "super-secret-auth-token-value")
        tmp_config.set("twitter_ct0", "long-ct0-value-12345")
        tmp_config.set("xhs_cookie", "xhs-cookie-value-long")
        tmp_config.set("bilibili_sessdata", "sessdata-value-long")
        tmp_config.set("bilibili_csrf", "bili_jct_csrf_value")

        # Short secrets (length < 8)
        tmp_config.set("short_key", "abc")
        tmp_config.set("short_ct0", "ct0_12")
        tmp_config.set("short_csrf", "csrf_")

        # Falsy sensitive values
        tmp_config.set("empty_token", "")
        tmp_config.set("none_password", None)
        tmp_config.set("false_key", False)

        # Non-sensitive settings (must not contain keywords like "key", "token", etc.)
        tmp_config.set("normal_setting", "visible")
        tmp_config.set("falsy_setting", "")

        masked = tmp_config.to_dict()

        # Verify masking of long secrets
        assert masked["twitter_auth_token"] == "super-se..."
        assert masked["twitter_ct0"] == "long-ct0..."
        assert masked["xhs_cookie"] == "xhs-cook..."
        assert masked["bilibili_sessdata"] == "sessdata..."
        assert masked["bilibili_csrf"] == "bili_jct..."

        # Verify masking of short secrets with fixed length '*'
        assert masked["short_key"] == "****"
        assert masked["short_ct0"] == "****"
        assert masked["short_csrf"] == "****"

        # Verify preservation of falsy values
        assert masked["empty_token"] == ""
        assert masked["none_password"] is None
        assert masked["false_key"] is False

        # Verify non-sensitive settings are untouched
        assert masked["normal_setting"] == "visible"
        assert masked["falsy_setting"] == ""
