# -*- coding: utf-8 -*-
import os
import stat
import sys
from pathlib import Path
import pytest
from agent_reach.config import Config

def test_sensitive_masking_enhancement(tmp_path):
    config_file = tmp_path / "config.yaml"
    config = Config(config_path=config_file)

    # Existing masking
    config.set("exa_api_key", "secret_exa_key_123456789")
    # New masking targets
    config.set("twitter_ct0", "secret_ct0_123456789")
    config.set("bilibili_sessdata", "secret_sessdata_123456789")
    config.set("bilibili_jct", "secret_jct_123456789")
    config.set("xhs_cookie", "secret_cookie_123456789")

    masked = config.to_dict()

    assert masked["exa_api_key"].startswith("secret_e")
    assert masked["exa_api_key"].endswith("...")

    # These currently fail (except sessdata because it contains 'data'? No, 'sessdata' contains nothing from 'key', 'token', 'password', 'proxy')
    # Actually 'sessdata' contains none of those.
    assert masked["twitter_ct0"].endswith("..."), f"twitter_ct0 was not masked: {masked['twitter_ct0']}"
    assert masked["bilibili_sessdata"].endswith("..."), f"bilibili_sessdata was not masked: {masked['bilibili_sessdata']}"
    assert masked["bilibili_jct"].endswith("..."), f"bilibili_jct was not masked: {masked['bilibili_jct']}"
    assert masked["xhs_cookie"].endswith("..."), f"xhs_cookie was not masked: {masked['xhs_cookie']}"

def test_permission_enforcement(tmp_path):
    if sys.platform == "win32":
        pytest.skip("Permission tests not applicable on Windows")

    config_dir = tmp_path / "secure_dir"
    config_file = config_dir / "config.yaml"

    # Pre-create file with loose permissions
    config_dir.mkdir()
    config_dir.chmod(0o755)
    config_file.touch()
    config_file.chmod(0o644)

    config = Config(config_path=config_file)
    config.save()

    # Check directory permissions
    dir_mode = config_dir.stat().st_mode & 0o777
    assert dir_mode == 0o700, f"Directory mode should be 0700, got {oct(dir_mode)}"

    # Check file permissions
    file_mode = config_file.stat().st_mode & 0o777
    assert file_mode == 0o600, f"File mode should be 0600, got {oct(file_mode)}"

if __name__ == "__main__":
    # Minimal runner if pytest not used directly
    try:
        test_sensitive_masking_enhancement(Path("/tmp"))
    except Exception as e:
        print(f"Masking test failed as expected: {e}")
