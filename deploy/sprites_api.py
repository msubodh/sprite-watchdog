#!/usr/bin/env python3
"""Tiny Sprites REST client used by the deploy scripts. Reads the agent's 24-hour
credentials from FLY_WD_CREDS (default ~/.config/fly-watchdog/creds.json, mode 600)
and refreshes them with the identity assertion when they are near expiry.
Never prints a token.

  sprites_api.py exec SPRITE 'bash command' [stdin-file]
  sprites_api.py call METHOD /path [json]
  sprites_api.py refresh
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CREDS = Path(os.path.expanduser(os.environ.get("FLY_WD_CREDS", "~/.config/fly-watchdog/creds.json")))


def creds() -> dict:
    return json.loads(CREDS.read_text())


def refresh(force: bool = False) -> dict:
    c = creds()
    age = time.time() - CREDS.stat().st_mtime
    if not force and age < 20 * 3600:
        return c
    data = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                   "assertion": c["identity_assertion"]}).encode()
    req = urllib.request.Request("https://fly.io/oauth2/token", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        new = json.loads(r.read())
    c.update({k: v for k, v in new.items() if v})
    old = os.umask(0o077)
    tmp = CREDS.with_suffix(".tmp")
    tmp.write_text(json.dumps(c))
    os.replace(tmp, CREDS)
    os.umask(old)
    print("refreshed agent credentials", file=sys.stderr)
    return c


def redact(text: str, c: dict) -> str:
    for k in ("access_token", "sprites_token", "identity_assertion"):
        if c.get(k):
            text = text.replace(c[k], "[REDACTED]")
    return text


def call(method: str, path: str, body: bytes | None = None, ctype: str = "application/json") -> tuple[int, str]:
    c = refresh()
    req = urllib.request.Request(c["sprites_api"].rstrip("/") + path, data=body, method=method,
                                 headers={"Authorization": "Bearer " + c["sprites_token"], "Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.status, redact(r.read().decode("utf-8", "replace"), c)
    except urllib.error.HTTPError as e:
        return e.code, redact(e.read().decode("utf-8", "replace"), c)


def exec_(sprite: str, cmd: str, stdin: bytes | None = None) -> tuple[int, str]:
    q = [("cmd", "bash"), ("cmd", "-c"), ("cmd", cmd)] + ([("stdin", "true")] if stdin is not None else [])
    return call("POST", f"/sprites/{sprite}/exec?" + urllib.parse.urlencode(q), stdin, "application/octet-stream")


def decode_frames(raw: str) -> str:
    # stdout frames start with \x01, stderr with \x02, exit frame \x03<code>
    return raw.replace("\x01", "").replace("\x02", "")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[0] == "refresh":
        refresh(force=True)
    elif a[0] == "exec":
        st, out = exec_(a[1], a[2], open(a[3], "rb").read() if len(a) > 3 else None)
        sys.stdout.write(f"HTTP {st}\n{decode_frames(out)}\n")
    elif a[0] == "call":
        st, out = call(a[1], a[2], a[3].encode() if len(a) > 3 else None)
        print(st)
        print(out[:20000])
