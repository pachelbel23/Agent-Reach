# Sentinel Security Journal 🛡️

This journal contains critical security learnings, unexpected side effects, or reusable patterns encountered in the Agent Reach codebase.

## 2026-03-16 - File Overwrites Do Not Enforce Mode on Existing Files
**Vulnerability:** On Unix-like systems, opening a file with `os.open` and specifying `O_CREAT` with restrictive permissions (such as `0o600`) does not apply the restrictive permissions to an existing file that was already created with broader permissions (e.g., `0o644`).
**Learning:** The OS permission bitmask passed to `os.open` only applies during file creation. When a file already exists, its permissions remain unchanged even if `O_CREAT` is passed.
**Prevention:** Always explicitly call `os.chmod` (or equivalent) when saving or overwriting sensitive configuration files to guarantee that permissions are properly restricted, even on existing files.

## 2026-03-16 - Masking Logic Exposing Short Sensitive Values and Missing Platform Identifiers
**Vulnerability:** A generic masking mechanism showing the first N characters of secrets can leak the entire secret if the secret is shorter than N characters. Additionally, relying on generic keywords (such as "key", "token", "password") failed to cover platform-specific session naming conventions (e.g., "ct0", "sessdata", "jct").
**Learning:** Sensitive data sanitization logic must be robust enough to handle short inputs using a fixed-length mask, and it must maintain an extensible, comprehensive list of platform-specific sensitive keywords.
**Prevention:** Implement a check for minimum length in masking utility functions, returning a fixed mask (like `****`) for short secrets, and explicitly include platform-specific credentials in sanitization checks.
