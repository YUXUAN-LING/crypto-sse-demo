from __future__ import annotations

import base64
from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp like '2026-02-27T12:34:56Z'."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def b64_encode(data: bytes) -> str:
    """Standard Base64 (with padding '=') for ciphertext/nonce fields."""
    return base64.b64encode(data).decode("ascii")


def b64_decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def b64url_encode(data: bytes) -> str:
    """
    Base64url (RFC 4648) without padding.
    Suitable for JSON keys, URLs, and filename-safe encoding.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    """
    Decode base64url without padding.
    Adds '=' padding back as needed.
    """
    s = s.strip()
    pad_len = (-len(s)) % 4
    s_padded = s + ("=" * pad_len)
    return base64.urlsafe_b64decode(s_padded.encode("ascii"))
