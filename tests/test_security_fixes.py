# -*- coding: utf-8 -*-
"""Regression and security-specific tests for Config."""

import os
import sys
import stat
from pathlib import Path
import pytest
from agent_reach.config import Config


def test_sensitive_masking(tmp_path):
    """Verify that sensitive config keys (including ct0, sessdata, jct, etc.) are masked properly."""
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    # Truthy sensitive keys (>= 8 chars and < 8 chars)
    config.set("twitter_ct0", "short")
    config.set("bilibili_sessdata", "very-long-sessdata-string-12345")
    config.set("bili_jct", "another_jct")
    config.set("normal_setting", "visible-data")

    # Falsy sensitive keys
    config.set("github_token", "")
    config.set("groq_api_key", False)

    masked = config.to_dict()

    # Short truthy sensitive should be ****
    assert masked["twitter_ct0"] == "****"
    # Long truthy sensitive should show first 8 chars and ...
    assert masked["bilibili_sessdata"] == "very-lon..."
    assert masked["bili_jct"] == "another_..."
    # Normal setting remains unchanged
    assert masked["normal_setting"] == "visible-data"
    # Falsy values are preserved
    assert masked["github_token"] == ""
    assert masked["groq_api_key"] is False


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """Verify that Config.save() restricts permissions to 0o600 even if the file pre-existed with broader access."""
    config_file = tmp_path / "config.yaml"

    # Pre-create config file with broad permissions
    config_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config_file, "w", encoding="utf-8") as f:
        f.write("foo: bar\n")

    if sys.platform != "win32" and os.name != "nt":
        os.chmod(config_file, 0o644)
        mode_before = config_file.stat().st_mode
        assert (stat.S_IMODE(mode_before) & 0o044) != 0

    config = Config(config_path=config_file)
    config.set("secret_key", "my-secret")  # saves configuration and enforces chmod

    if sys.platform != "win32" and os.name != "nt":
        mode_after = config_file.stat().st_mode
        # File should be owner-only read/write (0o600)
        assert stat.S_IMODE(mode_after) == 0o600


def test_config_permissions(tmp_path):
    """Verify permission enforcement is verified when targeting the configuration directory and file."""
    config_file = tmp_path / "subdir" / "config.yaml"
    config = Config(config_path=config_file)
    config.set("test_key", "value")

    if sys.platform != "win32" and os.name != "nt":
        dir_mode = config_file.parent.stat().st_mode
        # Directory should have 0o700 (owner read, write, execute)
        assert stat.S_IMODE(dir_mode) == 0o700

        file_mode = config_file.stat().st_mode
        # File should have 0o600 (owner read, write)
        assert stat.S_IMODE(file_mode) == 0o600
