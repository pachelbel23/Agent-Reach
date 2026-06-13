## 2025-05-14 - Hardening Configuration Security
**Vulnerability:** Configuration file and directory had world-readable permissions by default on Unix, and platform-specific secrets (Twitter's `ct0`, Bilibili's `SESSDATA`) were not masked in dictionary outputs.
**Learning:** `os.open` with `O_CREAT` and mode bits doesn't affect existing files; an explicit `os.chmod` is necessary to ensure restricted permissions on existing configuration files.
**Prevention:** Enforce `0o700` for config directories and `0o600` for sensitive YAML files during both initialization and save operations. Maintain a centralized list of sensitive keywords for consistent data masking.
