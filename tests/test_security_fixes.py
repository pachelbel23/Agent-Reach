# -*- coding: utf-8 -*-
"""Regression and security checks for Agent Reach."""

import os
import stat
import sys
import pytest
from pathlib import Path
from agent_reach.config import Config


def test_config_permissions(tmp_path):
    """Verify directory and file permissions are enforced correctly only on non-Windows."""
    config_file = tmp_path / "test_config" / "config.yaml"
    config = Config(config_path=config_file)

    # Trigger save to enforce permissions
    config.set("some_key", "some_value")

    if os.name != "nt":
        # Check directory permissions (should be 0o700)
        dir_mode = config.config_dir.stat().st_mode
        assert stat.S_IMODE(dir_mode) == 0o700

        # Check file permissions (should be 0o600)
        file_mode = config.config_path.stat().st_mode
        assert stat.S_IMODE(file_mode) == 0o600


def test_save_enforces_permissions_on_existing_file(tmp_path):
    """Config.save() should correct/reduce file permissions on existing files on Unix-like systems."""
    config_file = tmp_path / "existing_config.yaml"

    # Pre-create the file with broad permissions (e.g., 0o644)
    with open(config_file, "w", encoding="utf-8") as f:
        f.write("existing: data")

    if os.name != "nt":
        os.chmod(config_file, 0o644)
        assert stat.S_IMODE(config_file.stat().st_mode) == 0o644

    config = Config(config_path=config_file)
    config.set("key", "val")  # This calls save()

    if os.name != "nt":
        file_mode = config_file.stat().st_mode
        assert stat.S_IMODE(file_mode) == 0o600


def test_sensitive_masking(tmp_path):
    """Ensure sensitive tokens, cookies, ct0, sessdata, csrf, jct are masked, while transparent settings are unchanged."""
    config = Config(config_path=tmp_path / "mask_test.yaml")
    config.set("twitter_ct0", "abcdefghijklmnopqrstuvwxyz")
    config.set("bilibili_sessdata", "12345678901234567890")
    config.set("bilibili_csrf", "csrf_token_value_abc")
    config.set("xhs_cookie", "xhs_cookie_long_string_xyz")
    config.set("bili_jct", "jct_value_test_long")
    config.set("public_setting", "transparent_value")  # Devoid of sensitive keywords

    masked = config.to_dict()
    assert masked["twitter_ct0"] == "abcdefgh..."
    assert masked["bilibili_sessdata"] == "12345678..."
    assert masked["bilibili_csrf"] == "csrf_tok..."
    assert masked["xhs_cookie"] == "xhs_cook..."
    assert masked["bili_jct"] == "jct_valu..."
    assert masked["public_setting"] == "transparent_value"


def test_to_dict_masks_short_secrets(tmp_path):
    """Verify that sensitive values shorter than 8 characters are masked by a fixed-length **** string."""
    config = Config(config_path=tmp_path / "short_test.yaml")
    config.set("my_api_key", "abc")
    config.set("twitter_ct0", "short")
    config.set("some_token", "")
    config.set("normal_falsy", False)

    masked = config.to_dict()
    assert masked["my_api_key"] == "****"
    assert masked["twitter_ct0"] == "****"
    assert masked["some_token"] == ""  # Falsy sensitive preserved
    assert masked["normal_falsy"] is False  # Falsy non-sensitive preserved
