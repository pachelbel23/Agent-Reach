# -*- coding: utf-8 -*-
import os
import stat
import sys
import shutil
from pathlib import Path
import pytest
from agent_reach.config import Config

def test_masking_platform_identifiers(tmp_path):
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    sensitive_data = {
        "twitter_auth_token": "very_long_secret_auth_token_1234567890",
        "twitter_ct0": "very_long_secret_ct0_1234567890",
        "bilibili_sessdata": "very_long_secret_sessdata_1234567890",
        "bilibili_csrf": "very_long_secret_csrf_1234567890",
        "xhs_cookie": "very_long_secret_xhs_cookie_1234567890",
        "github_token": "very_long_secret_github_token_1234567890",
        "exa_api_key": "very_long_secret_exa_key_1234567890",
        "groq_api_key": "very_long_secret_groq_key_1234567890"
    }

    for k, v in sensitive_data.items():
        config.set(k, v)

    masked = config.to_dict()
    for k in sensitive_data:
        assert masked[k].endswith("...")
        # Ensure it doesn't leak the whole thing
        assert len(masked[k]) < len(sensitive_data[k])
        # It should only show the first 8 characters
        assert masked[k] == sensitive_data[k][:8] + "..."

def test_config_file_permissions_enforced(tmp_path):
    if sys.platform == "win32":
        pytest.skip("Permissions not enforced same way on Windows")

    config_file = tmp_path / "insecure.yaml"
    # Create file with broad permissions
    with open(config_file, "w") as f:
        f.write("test: data")
    os.chmod(config_file, 0o644)

    assert stat.S_IMODE(os.stat(config_file).st_mode) == 0o644

    config = Config(config_path=config_file)
    config.set("key", "value") # This triggers save()

    assert stat.S_IMODE(os.stat(config_file).st_mode) == 0o600

def test_config_dir_permissions_on_creation(tmp_path):
    if sys.platform == "win32":
        pytest.skip("Permissions not enforced same way on Windows")

    config_dir = tmp_path / "new_config_dir"
    config_file = config_dir / "config.yaml"

    assert not config_dir.exists()

    config = Config(config_path=config_file)

    assert config_dir.exists()
    assert stat.S_IMODE(os.stat(config_dir).st_mode) == 0o700

def test_masking_excludes_normal_keys(tmp_path):
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    config.set("user_name", "jules")
    config.set("theme", "dark")

    masked = config.to_dict()
    assert masked["user_name"] == "jules"
    assert masked["theme"] == "dark"
