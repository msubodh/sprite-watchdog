"""Shared wire protocol for fly-watchdog (Sprite side and devbox side).

Every message is authenticated with HMAC-SHA256 over a domain-separated string,
so a heartbeat signature can never be replayed as an order signature.

  heartbeat request  : "hb\n<ts>\n<nonce>\n<sha256(body)>"      (devbox -> Sprite)
  orders response    : "ord\n<request nonce>\n<sha256(body)>"   (Sprite -> devbox)

Binding the orders response to the request nonce means an old (captured)
response cannot be replayed to the devbox later.
Standard library only.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time

MAX_SKEW_S = 300
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
UNIT_RE = re.compile(r"^[a-z0-9][a-z0-9@._-]{0,62}\.(service|timer)$")


def _mac(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def new_nonce() -> str:
    return secrets.token_hex(16)


def sign_heartbeat(key: bytes, ts: int, nonce: str, body: bytes) -> str:
    return _mac(key, f"hb\n{ts}\n{nonce}\n{body_hash(body)}")


def verify_heartbeat(key: bytes, ts_s: str, nonce: str, sig: str, body: bytes, now: float | None = None) -> str | None:
    """Return None when valid, else a short reason. Nonce replay is checked by the caller."""
    now = time.time() if now is None else now
    if not ts_s or len(ts_s) > 12 or not ts_s.isdigit():
        return "bad-ts"
    if abs(now - int(ts_s)) > MAX_SKEW_S:
        return "stale-ts"
    if not NONCE_RE.match(nonce or ""):
        return "bad-nonce"
    if not sig or not hmac.compare_digest(sign_heartbeat(key, int(ts_s), nonce, body), sig):
        return "bad-sig"
    return None


def sign_orders(key: bytes, req_nonce: str, body: bytes) -> str:
    return _mac(key, f"ord\n{req_nonce}\n{body_hash(body)}")


def verify_orders(key: bytes, req_nonce: str, sig: str, body: bytes) -> bool:
    return bool(sig) and hmac.compare_digest(sign_orders(key, req_nonce, body), sig)
