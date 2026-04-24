# -*- coding: utf-8 -*-
import os
import stat
import pytest
from pathlib import Path
from agent_reach.config import Config

@pytest.fixture
def secure_config(tmp_path):
    config_file = tmp_path / ".agent-reach" / "config.yaml"
    return Config(config_path=config_file)

def test_sensitive_masking_gaps(secure_config):
    # These should be masked but currently are not
    secure_config.set("twitter_ct0", "secret_ct0_value_123456789")
    secure_config.set("bilibili_sessdata", "secret_sessdata_value_123456789")
    secure_config.set("xhs_cookie", "secret_cookie_value_123456789")
    secure_config.set("bilibili_csrf", "secret_csrf_value_123456789")

    masked = secure_config.to_dict()

    # Verify sensitive values are masked
    assert masked["twitter_ct0"] == "secret_c..."
    assert masked["bilibili_sessdata"] == "secret_s..."
    assert masked["xhs_cookie"] == "secret_c..."
    assert masked["bilibili_csrf"] == "secret_c..."

def test_config_dir_permissions(tmp_path):
    config_dir = tmp_path / ".agent-reach"
    config_file = config_dir / "config.yaml"

    # This will trigger _ensure_dir
    Config(config_path=config_file)

    if os.name != 'nt':
        mode = config_dir.stat().st_mode
        # Directory should be 0o700 (drwx------)
        assert stat.S_IMODE(mode) == 0o700

def test_config_file_permissions_fix_existing(tmp_path):
    config_dir = tmp_path / ".agent-reach"
    config_dir.mkdir()
    config_file = config_dir / "config.yaml"

    # Pre-create file with wide permissions
    config_file.touch()
    os.chmod(config_file, 0o644)

    config = Config(config_path=config_file)
    config.set("secret", "value") # Should trigger save()

    if os.name != 'nt':
        mode = config_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600
