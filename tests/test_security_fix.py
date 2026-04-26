
import os
import stat
import shutil
import pytest
from pathlib import Path
from agent_reach.config import Config

def test_sensitive_data_masking():
    # Use a dummy path for config
    config = Config(config_path=Path("test_masking_config.yaml"))
    try:
        config.set("twitter_ct0", "secret_ct0_value")
        config.set("xhs_cookie", "secret_xhs_cookie")
        config.set("bilibili_sessdata", "secret_sessdata")
        config.set("bilibili_csrf", "secret_csrf")
        config.set("some_api_key", "secret_key")

        masked = config.to_dict()

        # Check that specific platform tokens are masked
        assert "..." in str(masked.get("twitter_ct0"))
        assert "..." in str(masked.get("xhs_cookie"))
        assert "..." in str(masked.get("bilibili_sessdata"))
        assert "..." in str(masked.get("bilibili_csrf"))
        assert "..." in str(masked.get("some_api_key"))

        # Sanity check: non-sensitive keys should NOT be masked
        config.set("some_other_setting", "normal_value")
        masked = config.to_dict()
        assert masked.get("some_other_setting") == "normal_value"
    finally:
        if os.path.exists("test_masking_config.yaml"):
            os.remove("test_masking_config.yaml")

@pytest.mark.skipif(os.name == "nt", reason="Unix permissions not applicable on Windows")
def test_permissions_enforcement(tmp_path):
    test_dir = tmp_path / ".agent-reach-test"
    config_path = test_dir / "config.yaml"

    # 1. Test directory creation with restrictive permissions
    config = Config(config_path=config_path)
    config.set("test_key", "test_value")

    dir_mode = os.stat(test_dir).st_mode & 0o777
    file_mode = os.stat(config_path).st_mode & 0o777

    assert dir_mode == 0o700
    assert file_mode == 0o600

    # 2. Test correction of existing file permissions
    os.chmod(config_path, 0o644)
    assert (os.stat(config_path).st_mode & 0o777) == 0o644

    config.save()
    assert (os.stat(config_path).st_mode & 0o777) == 0o600

    # 3. Test correction of existing directory permissions
    os.chmod(test_dir, 0o755)
    assert (os.stat(test_dir).st_mode & 0o777) == 0o755

    # We need to trigger something that calls _ensure_dir or save
    config.save()
    assert (os.stat(test_dir).st_mode & 0o777) == 0o700
