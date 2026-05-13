## 2025-05-14 - Configuration Permissions and Atomic Creation
**Vulnerability:** Configuration file `~/.agent-reach/config.yaml` and its directory could be created or exist with overly permissive permissions (e.g., world-readable), potentially leaking sensitive API tokens and cookies to other users on the same system.

**Learning:** `os.open` with `O_CREAT` and a mode bitmask (e.g., `0o600`) correctly sets permissions for *newly created* files, which is good for avoiding race conditions. However, if the file already exists, `os.open` does NOT modify its permissions. An explicit `os.chmod` is required to ensure that existing files with loose permissions are also secured upon the next save. Similarly, `Path.mkdir(exist_ok=True)` doesn't enforce permissions on existing directories.

**Prevention:** Use `os.open` with restrictive modes for atomic creation, but ALWAYS follow up with an explicit `os.chmod` to enforce the desired security state regardless of whether the file/directory previously existed. Use `os.name != 'nt'` to guard these POSIX-specific calls.
