
import os
import shutil
import pytest
from pathlib import Path
from agent_reach.config import Config

def test_masking_comprehensive():
    config = Config(config_path=Path("test_config_security.yaml"))

    # Standard keys
    config.set("api_key", "secret123")
    config.set("github_token", "github_token_val")
    config.set("password", "pass123")
    config.set("reddit_proxy", "proxy_val")

    # Platform specific keys (newly added)
    config.set("twitter_ct0", "ct0_val")
    config.set("bilibili_sessdata", "sessdata_val")
    config.set("bilibili_csrf", "csrf_val")
    config.set("xhs_cookie", "cookie_val")
    config.set("auth_token", "auth_val")
    config.set("bili_jct", "jct_val")

    # Non-sensitive keys
    config.set("version", "1.0.0")
    config.set("feature_enabled", True)

    masked = config.to_dict()

    sensitive_keys = [
        "api_key", "github_token", "password", "reddit_proxy",
        "twitter_ct0", "bilibili_sessdata", "bilibili_csrf",
        "xhs_cookie", "auth_token", "bili_jct"
    ]

    for key in sensitive_keys:
        val = masked.get(key)
        assert val is not None, f"{key} is missing from masked dict"
        assert "..." in str(val), f"{key} was NOT masked! Value: {val}"
        assert str(val) != "None", f"{key} was masked to None string"

    # Verify non-sensitive are NOT masked
    assert masked.get("version") == "1.0.0", f"'version' was unexpectedly masked: {masked.get('version')}"

    if os.path.exists("test_config_security.yaml"):
        os.remove("test_config_security.yaml")

def test_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("Skipping permission tests on Windows")

    test_dir = tmp_path / "test_security_dir"
    config_path = test_dir / "config.yaml"

    # Test directory creation permissions
    config = Config(config_path=config_path)
    config.set("test", "value")

    dir_mode = os.stat(test_dir).st_mode & 0o777
    assert dir_mode == 0o700, f"Directory permissions are {oct(dir_mode)}, expected 0o700"

    file_mode = os.stat(config_path).st_mode & 0o777
    assert file_mode == 0o600, f"File permissions are {oct(file_mode)}, expected 0o600"

    # Test existing file permission correction
    os.chmod(config_path, 0o644)
    config.set("test2", "value2") # Triggers save() and chmod()

    file_mode = os.stat(config_path).st_mode & 0o777
    assert file_mode == 0o600, f"File permissions were NOT corrected to 0o600. Current: {oct(file_mode)}"

    # Test existing directory permission correction
    os.chmod(test_dir, 0o755)
    config.set("test3", "value3") # Triggers save() -> _ensure_dir() -> chmod()

    dir_mode = os.stat(test_dir).st_mode & 0o777
    assert dir_mode == 0o700, f"Directory permissions were NOT corrected to 0o700. Current: {oct(dir_mode)}"
