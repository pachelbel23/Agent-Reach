
import os
import pytest
from agent_reach.config import Config

def test_masking_of_sensitive_session_keys():
    config = Config()
    config.data = {
        "twitter_auth_token": "secret_token_123",
        "twitter_ct0": "secret_ct0_456",
        "bilibili_sessdata": "bili_secret_789",
        "bilibili_csrf": "bili_jct_abc",
        "xhs_cookie": "xhs_all_cookies_xyz",
        "normal_key": "public_value"
    }

    masked = config.to_dict()

    # These are already covered by "token"
    assert masked["twitter_auth_token"] == "secret_t..."

    # These are currently NOT covered but SHOULD be
    assert masked["twitter_ct0"] == "secret_c..."
    assert masked["bilibili_sessdata"] == "bili_sec..."
    assert masked["bilibili_csrf"] == "bili_jct..."
    assert masked["xhs_cookie"] == "xhs_all_..."

    # Normal key should remain untouched
    # Note: 'normal_key' contains 'key' which is a sensitive keyword, so it WILL be masked.
    # We should use a key that doesn't contain any sensitive keywords.
    assert "public_v" in masked["normal_key"]

def test_masking_of_truly_normal_key():
    config = Config()
    config.data = {
        "other": "public_value"
    }
    masked = config.to_dict()
    assert masked["other"] == "public_value"

def test_config_directory_permissions(tmp_path):
    # We want to ensure that Config ensures 0o700 on the directory
    config_dir = tmp_path / ".agent-reach"
    config_path = config_dir / "config.yaml"

    config = Config(config_path=config_path)
    config.save()

    import stat
    mode = os.stat(config_dir).st_mode
    assert stat.S_IMODE(mode) == 0o700

    mode = os.stat(config_path).st_mode
    assert stat.S_IMODE(mode) == 0o600
