import os
import shutil
import stat
from pathlib import Path
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

    test_config.unlink()

def test_config_permissions():
    if os.name == "nt":
        return # Skip on Windows

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

if __name__ == "__main__":
    # Run tests manually
    try:
        test_sensitive_masking()
        print("test_sensitive_masking passed")
        test_config_permissions()
        print("test_config_permissions passed")
    except Exception as e:
        import traceback
        traceback.print_exc()
        exit(1)
