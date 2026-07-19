# -*- coding: utf-8 -*-
"""Security-focused regression tests for Agent Reach."""

import os
import shutil
import stat
from pathlib import Path
import pytest
from agent_reach.config import Config


def test_sensitive_masking():
    # Use a temporary config file
    test_config = Path("test_config_masking.yaml")
    if test_config.exists():
        test_config.unlink()

    config = Config(config_path=test_config)
    config.set("twitter_ct0", "sensitive_ct0_value_123456789")
    config.set("bilibili_sessdata", "sensitive_sessdata_value_123456789")
    config.set("bilibili_csrf", "sensitive_csrf_value_123456789")
    config.set("xhs_cookie", "sensitive_xhs_cookie_value_123456789")
    config.set("bili_jct", "sensitive_jct_value_123456789")
    config.set("normal_setting", "visible_data_here")

    # Short secrets
    config.set("github_token", "abc")
    config.set("exa_api_key", "1234567")

    # Falsy sensitive and non-sensitive values
    config.set("twitter_auth_token", "")
    config.set("normal_empty", "")
    config.set("normal_false", False)

    masked = config.to_dict()

    assert masked["twitter_ct0"] != "sensitive_ct0_value_123456789"
    assert "..." in masked["twitter_ct0"]

    assert masked["bilibili_sessdata"] != "sensitive_sessdata_value_123456789"
    assert "..." in masked["bilibili_sessdata"]

    assert masked["bilibili_csrf"] != "sensitive_csrf_value_123456789"
    assert "..." in masked["bilibili_csrf"]

    assert masked["xhs_cookie"] != "sensitive_xhs_cookie_value_123456789"
    assert "..." in masked["xhs_cookie"]

    assert masked["bili_jct"] != "sensitive_jct_value_123456789"
    assert "..." in masked["bili_jct"]

    # Short secrets should be masked by fixed-length ****
    assert masked["github_token"] == "****"
    assert masked["exa_api_key"] == "****"

    # Transparent / non-sensitive keys
    assert masked["normal_setting"] == "visible_data_here"
    assert masked["normal_empty"] == ""
    assert masked["normal_false"] is False

    # Falsy sensitive value should preserve its falsy status
    assert masked["twitter_auth_token"] == ""

    test_config.unlink()


def test_config_permissions():
    if os.name == "nt":
        pytest.skip("Skip on Windows")

    test_dir = Path("test_config_dir")
    if test_dir.exists():
        shutil.rmtree(test_dir)

    test_config = test_dir / "config.yaml"

    config = Config(config_path=test_config)
    config.set("foo", "bar")

    # Check directory permissions
    dir_mode = test_dir.stat().st_mode
    assert stat.S_IMODE(dir_mode) == 0o700

    # Check file permissions
    file_mode = test_config.stat().st_mode
    assert stat.S_IMODE(file_mode) == 0o600

    shutil.rmtree(test_dir)


def test_save_enforces_permissions_on_existing_file(tmp_path):
    if os.name == "nt":
        pytest.skip("Skip on Windows")

    config_file = tmp_path / "secure_config.yaml"

    # Create the file with wide permissions first
    config_file.touch()
    os.chmod(config_file, 0o666)
    assert (config_file.stat().st_mode & 0o777) == 0o666

    config = Config(config_path=config_file)
    config.set("some_key", "some_value")
    config.save()

    mode = config_file.stat().st_mode
    assert (mode & 0o777) == 0o600, "File permissions should be strictly 0o600"
