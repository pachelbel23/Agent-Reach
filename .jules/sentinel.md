## 2025-05-15 - Insecure configuration permissions and sensitive data leakage
**Vulnerability:** Configuration file and directory permissions were too permissive (e.g., 0644), and platform-specific session identifiers (ct0, sessdata, etc.) were not masked in configuration dumps.
**Learning:** Using os.open with O_CREAT and a mode bitmask only sets permissions for *newly created* files. Existing files retain their old permissions. Explicit os.chmod is necessary to ensure restrictive permissions on overwrites.
**Prevention:** Always use os.chmod(path, 0o600) on sensitive files and 0o700 on their parent directories. Maintain an exhaustive list of sensitive keywords for data masking.
