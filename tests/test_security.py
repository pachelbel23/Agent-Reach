# -*- coding: utf-8 -*-
import os
import stat
import sys
from pathlib import Path
import pytest
from agent_reach.config import Config

@pytest.fixture
def secure_config_dir(tmp_path):
    config_dir = tmp_path / ".agent-reach"
    config_path = config_dir / "config.yaml"
    return config_dir, config_path

class TestSecurity:
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
    def test_directory_permissions(self, secure_config_dir):
        config_dir, config_path = secure_config_dir
        # Config constructor calls _ensure_dir
        Config(config_path=config_path)

        mode = config_dir.stat().st_mode
        # Should be 0o700
        assert stat.S_IMODE(mode) == 0o700

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
    def test_file_permissions_on_creation(self, secure_config_dir):
        config_dir, config_path = secure_config_dir
        config = Config(config_path=config_path)
        config.set("some_key", "some_value")

        mode = config_path.stat().st_mode
        # Should be 0o600
        assert stat.S_IMODE(mode) == 0o600

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
    def test_file_permissions_enforced_on_existing_file(self, secure_config_dir):
        config_dir, config_path = secure_config_dir
        config_dir.mkdir(parents=True)

        # Create with loose permissions
        with open(config_path, "w") as f:
            f.write("test: value")
        os.chmod(config_path, 0o644)
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o644

        # Loading and setting should trigger save() which enforces 0o600
        config = Config(config_path=config_path)
        config.set("new_key", "new_value")

        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600

    def test_masking_platform_sensitive_values(self, secure_config_dir):
        _, config_path = secure_config_dir
        config = Config(config_path=config_path)

        sensitive_data = {
            "twitter_ct0": "ct0_value_123456789",
            "bilibili_sessdata": "sessdata_secret_abc",
            "bilibili_csrf": "csrf_token_xyz",
            "xhs_cookie": "xhs_cookie_content_here",
            "bili_jct": "jct_value_999",
            "auth_token": "auth_secret_token",
            "exa_api_key": "exa_key_12345",
            "proxy_url": "http://user:pass@proxy",
            "normal_value": "public_data"
        }

        for k, v in sensitive_data.items():
            config.set(k, v)

        masked = config.to_dict()

        # Verify masking
        assert masked["twitter_ct0"] == "ct0_valu..."
        assert masked["bilibili_sessdata"] == "sessdata..."
        assert masked["bilibili_csrf"] == "csrf_tok..."
        assert masked["xhs_cookie"] == "xhs_cook..."
        assert masked["bili_jct"] == "jct_valu..."
        assert masked["auth_token"] == "auth_sec..."
        assert masked["exa_api_key"] == "exa_key_..."
        assert masked["proxy_url"] == "http://u..."
        assert masked["normal_value"] == "public_data"
