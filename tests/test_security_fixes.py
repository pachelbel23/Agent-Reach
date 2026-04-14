# -*- coding: utf-8 -*-
import pytest
from agent_reach.config import Config

def test_masking_missing_keys(tmp_path):
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    sensitive_data = {
        "twitter_ct0": "secret_ct0_value",
        "bilibili_sessdata": "secret_sessdata_value",
        "bilibili_csrf": "secret_csrf_value",
        "xhs_cookie": "secret_xhs_cookie_value",
        "bili_jct": "secret_jct_value",
        "auth_token": "secret_auth_token_value"
    }

    for k, v in sensitive_data.items():
        config.set(k, v)

    masked = config.to_dict()

    for k in sensitive_data:
        assert masked[k] != sensitive_data[k], f"Key {k} was not masked!"
        assert masked[k].endswith("..."), f"Key {k} masking format incorrect"

def test_config_dir_permissions(tmp_path):
    import os
    import stat
    import sys

    if sys.platform == "win32":
        pytest.skip("Permissions tests not applicable on Windows")

    config_dir = tmp_path / "secure_dir"
    config_file = config_dir / "config.yaml"

    # This should trigger _ensure_dir
    config = Config(config_path=config_file)

    mode = os.stat(config_dir).st_mode
    # Should be 0o700
    assert stat.S_IMODE(mode) == 0o700, f"Directory permissions should be 0o700, got {oct(stat.S_IMODE(mode))}"
