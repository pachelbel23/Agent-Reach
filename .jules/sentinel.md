## 2025-05-22 - [Config Hardening]
**Vulnerability:** Weak configuration permissions and incomplete data masking. Existing `os.open` with `O_CREAT` did not fix permissions on existing files, and masking logic showed prefixes (8 chars) and missed platform session IDs.
**Learning:** `os.open` mode bits only apply at creation; `os.chmod` is required for self-healing. Masking should use fixed lengths to prevent metadata leaks.
**Prevention:** Use explicit `os.chmod` after saving sensitive files. Centralize sensitive keyword lists for all supported platforms (e.g., `ct0`, `sessdata`).
