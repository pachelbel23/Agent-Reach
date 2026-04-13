# -*- coding: utf-8 -*-
import os
import stat
import sys
import shutil
from pathlib import Path
import pytest
from agent_reach.config import Config

@pytest.fixture
def secure_tmp_dir(tmp_path):
    d = tmp_path / "secure_config_test"
    d.mkdir()
    yield d
    if d.exists():
        shutil.rmtree(d)

def test_masking_comprehensive(secure_tmp_dir):
    config_path = secure_tmp_dir / "config.yaml"
    config = Config(config_path=config_path)

    sensitive_data = {
        "twitter_auth_token": "secret_auth_token_12345",
        "twitter_ct0": "secret_ct0_12345",
        "xhs_cookie": "secret_xhs_cookie_12345",
        "bilibili_sessdata": "secret_sessdata_12345",
        "bilibili_csrf": "secret_csrf_12345",
        "github_token": "secret_github_token_12345",
        "exa_api_key": "secret_exa_api_key_12345",
        "groq_api_key": "secret_groq_api_key_12345",
        "reddit_proxy": "http://user:pass@ip:port",
        "my_password": "super_secret_password",
        "bili_jct": "secret_jct_12345",
    }

    for k, v in sensitive_data.items():
        config.set(k, v)

    config.set("public_setting", "i_am_visible")

    masked = config.to_dict()

    for k in sensitive_data:
        assert masked[k].endswith("..."), f"{k} should be masked"
        assert len(masked[k]) <= 11 # 8 chars + 3 dots

    assert masked["public_setting"] == "i_am_visible"

@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions tests")
def test_directory_permissions(secure_tmp_dir):
    # Create a config in a new subdir to test directory creation permissions
    config_dir = secure_tmp_dir / "new_config_dir"
    config_path = config_dir / "config.yaml"

    # Pre-create with loose permissions
    config_dir.mkdir()
    os.chmod(config_dir, 0o777)

    config = Config(config_path=config_path)
    config.set("test", "value")

    mode = os.stat(config_dir).st_mode
    assert stat.S_IMODE(mode) == 0o700, "Directory should be restricted to 0700"

@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions tests")
def test_file_permissions_correction(secure_tmp_dir):
    config_path = secure_tmp_dir / "config.yaml"

    # Pre-create file with loose permissions
    config_path.touch()
    os.chmod(config_path, 0o666)

    config = Config(config_path=config_path)
    config.set("secret", "data")

    mode = os.stat(config_path).st_mode
    assert stat.S_IMODE(mode) == 0o600, "File should be restricted to 0600"
