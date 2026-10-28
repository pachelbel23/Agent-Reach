"""Text helpers."""

from __future__ import annotations

import re

_URL_CREDENTIALS_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9+.\-]{0,19}://)[^/\s@]+@"
)
_BARE_USERINFO_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[^:/\s@]+:[^/\s@]+@(?=[A-Za-z0-9.\-\[])"
)
# Redact sensitive parameters (including tokens, keys, secrets, session IDs, and auth headers)
# from URLs in diagnostic logs and error responses to prevent credential exposure.
_URL_QUERY_SECRET_RE = re.compile(
    r"([?&#](?:"
    r"(?:[a-z0-9_.-]*[_-])?"
    r"(?:access[_-]?token|refresh[_-]?token|id[_-]?token|auth(?:orization)?(?:[_-]?token)?|token|bearer|"
    r"api[_-]?key|x[_-]?api[_-]?key|key|password|passwd|passcode|secret|client[_-]?secret|app[_-]?secret|private[_-]?key|"
    r"signature|sig|session(?:[_-]?token|[_-]?id)?|cookie|credential)"
    r")=)[^&#\s]*",
    re.IGNORECASE,
)


def scrub_url_credentials(text: object) -> str:
    """Redact URL userinfo and sensitive query/fragment values from text."""
    scrubbed = _URL_CREDENTIALS_RE.sub(r"\1***@", str(text))
    scrubbed = _BARE_USERINFO_RE.sub("***@", scrubbed)
    return _URL_QUERY_SECRET_RE.sub(r"\1***", scrubbed)
