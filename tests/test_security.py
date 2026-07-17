# -*- coding: utf-8 -*-
"""Security-focused tests for Agent Reach configuration."""

import os
import stat
from pathlib import Path

import pytest

from agent_reach.config import Config


def test_config_directory_permissions(tmp_path, monkeypatch):
    """Verify that Config enforces 0o700 permissions on its CONFIG_DIR."""
    custom_dir = tmp_path / ".agent-reach-test"
    monkeypatch.setattr(Config, "CONFIG_DIR", custom_dir)
    monkeypatch.setattr(Config, "CONFIG_FILE", custom_dir / "config.yaml")

    config = Config()

    if os.name != "nt":
        mode = custom_dir.stat().st_mode
        assert (mode & 0o777) == 0o700, "Directory permissions should be 0o700"


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """Verify that Config.save() restricts permissions on an existing file with wider access."""
    config_file = tmp_path / "secure_config.yaml"

    # Create the file with wide permissions first
    config_file.touch()
    if os.name != "nt":
        os.chmod(config_file, 0o666)
        assert (config_file.stat().st_mode & 0o777) == 0o666

    config = Config(config_path=config_file)
    config.set("some_key", "some_value")
    config.save()

    if os.name != "nt":
        mode = config_file.stat().st_mode
        assert (mode & 0o777) == 0o600, "File permissions should be strictly 0o600"


def test_to_dict_masks_platform_specific_secrets(tmp_path):
    """Verify that platform-specific secrets like ct0, sessdata, and jct are masked."""
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    config.set("twitter_ct0", "ct0-secret-value-long")
    config.set("bili_sessdata", "sessdata-secret-value-long")
    config.set("bili_jct", "jct-secret-value-long")

    masked = config.to_dict()
    assert masked["twitter_ct0"] == "ct0-secr..."
    assert masked["bili_sessdata"] == "sessdata..."
    assert masked["bili_jct"] == "jct-secr..."


def test_to_dict_masks_short_secrets(tmp_path):
    """Verify that short secrets are masked by a fixed-length **** string."""
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    config.set("twitter_ct0", "abc")
    config.set("my_token", "1234567")

    masked = config.to_dict()
    assert masked["twitter_ct0"] == "****"
    assert masked["my_token"] == "****"
