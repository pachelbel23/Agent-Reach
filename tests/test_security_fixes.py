# -*- coding: utf-8 -*-
import os
import stat
from pathlib import Path
import pytest
from agent_reach.config import Config

def test_config_masking():
    config = Config()
    config.data = {
        "exa_api_key": "secret_exa_key_long_value",
        "github_token": "secret_github_token_long_value",
        "twitter_ct0": "secret_ct0_long_value",
        "xhs_cookie": "secret_xhs_cookie_long_value",
        "bilibili_sessdata": "secret_sessdata_long_value",
        "bilibili_csrf": "secret_csrf_long_value",
        "bili_jct": "secret_jct_long_value",
        "some_password": "secret_password_long_value"
    }

    masked = config.to_dict()

    sensitive_keys = [
        "exa_api_key", "github_token", "twitter_ct0",
        "xhs_cookie", "bilibili_sessdata", "bilibili_csrf",
        "bili_jct", "some_password"
    ]

    for key in sensitive_keys:
        assert "..." in masked[key], f"{key} NOT masked: {masked[key]}"
        assert masked[key].startswith("secret_"), f"{key} masking format wrong: {masked[key]}"

def test_config_directory_permissions(tmp_path):
    config_dir = tmp_path / ".agent-reach-test"
    config_file = config_dir / "config.yaml"

    # Initialize config with custom path
    config = Config(config_path=config_file)
    config.set("test", "value")

    assert config_dir.exists()

    if os.name != "nt":
        mode = os.stat(config_dir).st_mode
        # Check that it's 0o700 (drwx------)
        assert stat.S_IMODE(mode) == 0o700

        mode_file = os.stat(config_file).st_mode
        # Check that it's 0o600 (-rw-------)
        assert stat.S_IMODE(mode_file) == 0o600

def test_existing_directory_permissions_correction(tmp_path):
    if os.name == "nt":
        pytest.skip("chmod behavior different on Windows")

    config_dir = tmp_path / ".agent-reach-test-correction"
    config_dir.mkdir(parents=True)
    # Set broad permissions
    os.chmod(config_dir, 0o775)

    config_file = config_dir / "config.yaml"

    # Initialize config should correct permissions
    config = Config(config_path=config_file)

    mode = os.stat(config_dir).st_mode
    assert stat.S_IMODE(mode) == 0o700
