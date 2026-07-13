# -*- coding: utf-8 -*-
"""Security tests for Agent Reach."""

import os
import stat
import sys
from pathlib import Path
import pytest
from agent_reach.config import Config

@pytest.fixture
def tmp_config_path(tmp_path):
    return tmp_path / "config.yaml"

def test_to_dict_masks_platform_specific_secrets(tmp_config_path):
    """Verify that platform-specific secret keys are masked in to_dict()."""
    config = Config(config_path=tmp_config_path)

    secrets = {
        "twitter_ct0": "secret_ct0_value",
        "bilibili_sessdata": "secret_sessdata_value",
        "bilibili_csrf": "secret_csrf_value",
        "xhs_cookie": "secret_xhs_cookie",
        "some_jct": "secret_jct"
    }

    for k, v in secrets.items():
        config.set(k, v)

    masked = config.to_dict()

    for k, v in secrets.items():
        assert masked[k] != v, f"Leak: {k} was not masked!"
        assert masked[k].endswith("..."), f"Masking format error for {k}"

def test_to_dict_masks_short_secrets(tmp_config_path):
    """Verify that short secrets are masked securely."""
    config = Config(config_path=tmp_config_path)
    config.set("my_api_key", "short")

    masked = config.to_dict()
    assert masked["my_api_key"] == "****", "Short secret should be completely masked"

@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
def test_save_enforces_permissions_on_existing_file(tmp_config_path):
    """Verify that save() corrects permissions on an existing file with loose perms."""
    # Create file with loose permissions
    with open(tmp_config_path, "w") as f:
        f.write("{}")
    os.chmod(tmp_config_path, 0o644)

    initial_mode = tmp_config_path.stat().st_mode & 0o777
    assert initial_mode == 0o644

    config = Config(config_path=tmp_config_path)
    config.set("key", "value") # triggers save()

    final_mode = tmp_config_path.stat().st_mode & 0o777
    assert final_mode == 0o600, f"Expected 0o600, got {oct(final_mode)}"

@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
def test_config_directory_permissions(tmp_path):
    """Verify that the config directory is created with 0o700 permissions."""
    config_dir = tmp_path / "new_secure_dir"
    config_file = config_dir / "config.yaml"

    # Config init calls _ensure_dir
    Config(config_path=config_file)

    assert config_dir.exists()
    mode = config_dir.stat().st_mode & 0o777
    assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"
