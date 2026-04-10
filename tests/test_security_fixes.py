# -*- coding: utf-8 -*-
import os
import pytest
from agent_reach.config import Config

def test_to_dict_masks_all_sensitive_platforms(tmp_path):
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    # Platform-specific sensitive data
    config.set("twitter_ct0", "sensitive_ct0_value")
    config.set("bilibili_sessdata", "sensitive_sessdata_value")
    config.set("bilibili_csrf", "sensitive_csrf_value")
    config.set("xhs_cookie", "sensitive_cookie_value")
    config.set("bili_jct", "sensitive_jct_value")

    masked = config.to_dict()

    assert masked["twitter_ct0"] == "sensitiv..."
    assert masked["bilibili_sessdata"] == "sensitiv..."
    assert masked["bilibili_csrf"] == "sensitiv..."
    assert masked["xhs_cookie"] == "sensitiv..."
    assert masked["bili_jct"] == "sensitiv..."

def test_config_dir_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("Permission checks not applicable on Windows")

    config_dir = tmp_path / "secure_dir"
    config_file = config_dir / "config.yaml"

    # Ensure dir didn't exist
    assert not config_dir.exists()

    config = Config(config_path=config_file)
    config.save()

    import stat
    mode = os.stat(config_dir).st_mode
    assert stat.S_IMODE(mode) == 0o700
