# -*- coding: utf-8 -*-
"""Security and permissions tests for Agent Reach config module."""

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


def test_to_dict_masks_platform_specific_secrets(tmp_config):
    """Test that platform-specific secrets like ct0, sessdata, csrf, jct, cookie are masked."""
    tmp_config.set("twitter_ct0", "my-secret-twitter-ct0-val")
    tmp_config.set("bilibili_sessdata", "my-secret-sessdata-val")
    tmp_config.set("bilibili_csrf", "my-secret-csrf-val")
    tmp_config.set("bilibili_jct", "my-secret-jct-val")
    tmp_config.set("xhs_cookie", "my-secret-cookie-val")

    masked = tmp_config.to_dict()
    assert masked["twitter_ct0"] == "my-secre..."
    assert masked["bilibili_sessdata"] == "my-secre..."
    assert masked["bilibili_csrf"] == "my-secre..."
    assert masked["bilibili_jct"] == "my-secre..."
    assert masked["xhs_cookie"] == "my-secre..."


def test_to_dict_masks_short_secrets(tmp_config):
    """Test that sensitive values under 8 characters are masked with ****."""
    tmp_config.set("exa_api_key", "abc")
    tmp_config.set("github_token", "1234567")

    masked = tmp_config.to_dict()
    assert masked["exa_api_key"] == "****"
    assert masked["github_token"] == "****"


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """Verify that Config.save() restricts permissions on an existing file with broad access."""
    config_file = tmp_path / "existing_config.yaml"

    # Pre-create the file with broad permissions (e.g., readable by others)
    config_file.touch()
    if sys.platform != "win32":
        os.chmod(config_file, 0o666)
        mode_before = config_file.stat().st_mode
        assert (mode_before & stat.S_IRGRP), "Pre-condition: Group read should be set"
        assert (mode_before & stat.S_IROTH), "Pre-condition: Other read should be set"

    config = Config(config_path=config_file)
    config.set("secret_key", "supersecret")

    if sys.platform != "win32":
        mode_after = config_file.stat().st_mode
        assert not (mode_after & stat.S_IRGRP), "Group read should be disabled after save"
        assert not (mode_after & stat.S_IROTH), "Other read should be disabled after save"


def test_config_directory_permissions(tmp_path, monkeypatch):
    """Verify that Config._ensure_dir() restricts permissions on the config directory."""
    # Use monkeypatch to override Config.CONFIG_DIR
    target_dir = tmp_path / "app_config_dir"
    monkeypatch.setattr(Config, "CONFIG_DIR", target_dir)
    monkeypatch.setattr(Config, "CONFIG_FILE", target_dir / "config.yaml")

    # This should trigger directory creation with correct permissions
    config = Config()

    if sys.platform != "win32":
        dir_mode = target_dir.stat().st_mode
        assert not (dir_mode & stat.S_IRGRP), "Directory group read should be disabled"
        assert not (dir_mode & stat.S_IROTH), "Directory other read should be disabled"
        assert not (dir_mode & stat.S_IXGRP), "Directory group execute should be disabled"
        assert not (dir_mode & stat.S_IXOTH), "Directory other execute should be disabled"
