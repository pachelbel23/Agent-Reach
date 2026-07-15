# -*- coding: utf-8 -*-
"""Security tests for Agent Reach."""

import pytest
from agent_reach.config import Config

class TestSecurity:
    def test_to_dict_masks_platform_specific_secrets(self, tmp_path):
        """Verify that platform-specific identifiers like ct0 and sessdata are masked."""
        config_file = tmp_path / "config.yaml"
        config = Config(config_path=config_file)

        secrets = {
            "twitter_ct0": "sensitive_twitter_ct0_value",
            "bilibili_sessdata": "sensitive_bilibili_sessdata_value",
            "bilibili_csrf": "sensitive_bilibili_csrf_value",
            "xhs_cookie": "sensitive_xhs_cookie_value",
            "bili_jct": "sensitive_bili_jct_value",
            "my_password": "super-secret-password",
            "api_key": "some-api-key-12345",
            "github_token": "ghp_sometoken1234567890",
            "reddit_proxy": "http://user:pass@1.2.3.4:8080"
        }

        for k, v in secrets.items():
            config.set(k, v)

        masked = config.to_dict()

        for k in secrets:
            # Check that it's masked
            assert masked[k].endswith("...")
            # Check that it doesn't contain the full sensitive value
            assert secrets[k] != masked[k]
            # Verify that sensitive parts are mostly gone
            if len(secrets[k]) > 15:
                assert secrets[k][12:] not in str(masked[k])

    def test_to_dict_masks_short_secrets(self, tmp_path):
        """Verify that short secrets are masked with a fixed mask, not showing any prefix."""
        config_file = tmp_path / "config.yaml"
        config = Config(config_path=config_file)

        config.set("short_key", "123")
        masked = config.to_dict()
        assert masked["short_key"] == "****"

    def test_to_dict_does_not_mask_normal_keys(self, tmp_path):
        """Verify that non-sensitive keys are preserved."""
        config_file = tmp_path / "config.yaml"
        config = Config(config_path=config_file)

        config.set("app_name", "agent-reach")
        config.set("version", "1.3.0")
        config.set("verbose", True)

        masked = config.to_dict()
        assert masked["app_name"] == "agent-reach"
        assert masked["version"] == "1.3.0"
        assert masked["verbose"] is True

    def test_to_dict_handles_empty_values(self, tmp_path):
        """Verify that empty or None values are handled correctly."""
        config_file = tmp_path / "config.yaml"
        config = Config(config_path=config_file)

        config.set("empty_key", "")
        config.set("none_key", None)

        masked = config.to_dict()
        assert masked["empty_key"] == ""
        assert masked["none_key"] is None
