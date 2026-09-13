## 2025-05-18 - POSIX File Permissions and os.open Behavior

**Vulnerability:** Pre-existing configuration files (`~/.agent-reach/config.yaml`) retain loose permissions (e.g., `0o644`) when saved/updated via `os.open` with `O_CREAT`, potentially exposing API tokens and session cookies to local users on shared systems.

**Learning:** `os.open(..., O_CREAT | O_WRONLY | O_TRUNC, mode)` in Python/POSIX only applies the `mode` mask when creating a *new* file. If the file already exists, its mode bitmask remains unchanged regardless of the `mode` parameter passed to `os.open`. Furthermore, the config directory (`~/.agent-reach`) was created with system default umask (often `0o755` or `0o775`).

**Prevention:** Always explicitly call `os.chmod(path, 0o600)` on sensitive configuration/credential files after saving, and call `os.chmod(dir_path, 0o700)` during directory initialization on non-Windows platforms (`os.name != "nt"`).
