#!/usr/bin/env python3
"""watchdog_link: the devbox half of fly-watchdog. Runs every 5 minutes (user timer).

1. Collects a small, sanitized health snapshot (no secrets, no hostnames, no IPs).
2. Pushes it OUTBOUND to the Sprite as an HMAC-signed heartbeat. Nothing on the
   devbox listens for the watchdog; Fly gets no SSH key and no shell.
3. The Sprite's signed reply may carry "kick" requests. Each one is re-checked here
   against a hard-coded allowlist, expiry, replay and rate limits, and only then
   runs exactly `systemctl --user start --no-block <unit>` (argv list, no shell).
   `start` never stops or kills a running process; on an active unit it is a no-op.

Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import wdproto  # noqa: E402

# The only units the watchdog may ever ask to start. A config file can narrow this
# list but never widen it (intersection), so a tampered config cannot add units.
HARD_ALLOWLIST = frozenset({
    "job-supervisor.service",
    "job-supervisor.timer",
    "jobs-sync.service",
    "jobs-sync.timer",
})
MIN_INTERVAL_S = 1800  # per unit
MAX_PER_DAY = 6  # all units together
MAX_ORDERS_PER_REPLY = 4

CFG_PATH = Path(os.environ.get("WD_LINK_CONFIG", Path.home() / ".config/fly-watchdog/link.json"))
STATE_DIR = Path(os.environ.get("WD_LINK_STATE", Path.home() / ".local/state/fly-watchdog"))
PATH_RE = re.compile(r"/\S+")


def log(kind: str, **kw) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    rec = {"at": datetime.now().astimezone().isoformat(timespec="seconds"), "kind": kind, **kw}
    with open(STATE_DIR / "link-events.jsonl", "a") as f:  # append-only audit log
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def load_state() -> dict:
    try:
        return json.loads((STATE_DIR / "link-state.json").read_text())
    except (OSError, ValueError):
        return {"executed": {}, "runs": [], "acks": []}


def save_state(s: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    p = STATE_DIR / "link-state.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(s, sort_keys=True))
    os.replace(tmp, p)


# --------------------------------------------------------------------------- collect


def sh(argv: list[str], timeout: int = 10) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def http_ok(url: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as r:
            return r.status < 500, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return e.code < 500, f"HTTP {e.code}"
    except Exception as e:
        return False, f"unreachable ({type(e).__name__})"


def unit_active(unit: str, user: bool) -> tuple[bool, str]:
    st = sh(["systemctl", *(["--user"] if user else []), "is-active", unit]) or "unknown"
    return st == "active", st


def collect(cfg: dict) -> dict:
    checks = {}
    for c in cfg.get("local_checks", []):
        if c["type"] == "http":
            ok, d = http_ok(c["url"])
        elif c["type"] == "unit":
            ok, d = unit_active(c["unit"], c.get("user", True))
        else:
            continue
        checks[c["name"]] = {"ok": ok, "detail": d}

    sup_active, _ = unit_active("job-supervisor.timer", True)
    last = sh(["systemctl", "--user", "show", "job-supervisor.timer", "-p", "LastTriggerUSec", "--timestamp=unix"])
    m = re.search(r"@(\d+)", last)
    supervisor = {"timer_active": sup_active, "last_run_age_s": int(time.time() - int(m.group(1))) if m else None}

    jobs, idx_age = [], None
    if not cfg.get("jobs_json"):  # job reporting is optional
        return {"host": cfg.get("host_label", "server"), "checks": checks, "supervisor": supervisor,
                "jobs": [], "jobs_index_age_s": None}
    jobs_json = Path(cfg["jobs_json"])
    state_dir = jobs_json.parent / "state"
    try:
        with open(jobs_json, "rb") as f:
            d = json.loads(f.read(2_000_000))
        idx_age = int(time.time() - datetime.fromisoformat(d["generated_at"]).timestamp())
        report = set(cfg.get("report_jobs", []))
        for j in d.get("jobs", []):
            name = str(j.get("name", ""))
            if j.get("state") == "done" or (report and name not in report):
                continue
            age = None
            if j.get("last_progress_at"):
                age = int(time.time() - datetime.fromisoformat(j["last_progress_at"]).timestamp())
            status = ""
            sf = state_dir / f"{name}.status"
            if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,47}", name) and sf.is_file():
                status = PATH_RE.sub("<path>", sf.read_text(errors="replace").splitlines()[0] if sf.stat().st_size else "")[:120]
            jobs.append({"name": name, "state": j.get("state"), "progress_age_s": age, "status": status})
    except (OSError, ValueError, KeyError, TypeError):
        checks["jobs-index"] = {"ok": False, "detail": "jobs.json unreadable"}
    return {"host": cfg.get("host_label", "server"), "checks": checks, "supervisor": supervisor,
            "jobs": jobs[:40], "jobs_index_age_s": idx_age}


# --------------------------------------------------------------------------- orders


def allowed_units(cfg: dict) -> frozenset[str]:
    return HARD_ALLOWLIST & frozenset(cfg.get("allow_units", HARD_ALLOWLIST))


def vet(order: object, cfg: dict, state: dict, t: float) -> str | None:
    """Return None if the order may run, else the reason it is refused."""
    if not isinstance(order, dict):
        return "malformed"
    oid, unit = order.get("id"), order.get("unit")
    if not isinstance(oid, str) or not wdproto.NONCE_RE.match(oid):
        return "bad-id"
    if order.get("action") != "start_unit":
        return "action-not-allowed"
    if not isinstance(unit, str) or not wdproto.UNIT_RE.match(unit) or unit not in allowed_units(cfg):
        return "unit-not-allowed"
    exp, issued = order.get("expires_at"), order.get("issued_at")
    if not isinstance(exp, int) or exp < t or exp > t + 3600:
        return "expired"
    if not isinstance(issued, int) or issued > t + 300 or issued < t - 900 or exp <= issued:
        return "bad-issued-at"
    if oid in state["executed"]:
        return "replay"
    runs = [r for r in state["runs"] if r["t"] > t - 86400]
    if len(runs) >= MAX_PER_DAY:
        return "daily-limit"
    if any(r["unit"] == unit and r["t"] > t - MIN_INTERVAL_S for r in runs):
        return "too-soon"
    return None


def execute(unit: str) -> str:
    try:
        p = subprocess.run(["systemctl", "--user", "start", "--no-block", unit],
                           capture_output=True, text=True, timeout=30)
        return "started" if p.returncode == 0 else f"exit {p.returncode}"
    except (OSError, subprocess.TimeoutExpired) as e:
        return type(e).__name__


def handle_orders(orders: list, cfg: dict, state: dict) -> None:
    t = time.time()
    for o in orders[:MAX_ORDERS_PER_REPLY]:
        why = vet(o, cfg, state, t)
        oid = o.get("id") if isinstance(o, dict) and isinstance(o.get("id"), str) else "?"
        if why:
            log("order-refused", order=oid[:8], unit=str(o.get("unit") if isinstance(o, dict) else "")[:64], reason=why)
            if why != "replay" and wdproto.NONCE_RE.match(oid):
                state["executed"][oid] = t
                state["acks"].append({"id": oid, "result": f"refused:{why}"})
            continue
        result = "dry-run" if cfg.get("dry_run") else execute(o["unit"])
        state["executed"][oid] = t
        state["runs"].append({"t": t, "unit": o["unit"]})
        state["acks"].append({"id": oid, "result": result})
        log("order-executed", order=oid[:8], unit=o["unit"], result=result)
    # bounded memory
    recent = sorted(((v, k) for k, v in state["executed"].items() if v > t - 7 * 86400), reverse=True)[:5000]
    state["executed"] = {k: v for v, k in recent}
    state["runs"] = [r for r in state["runs"] if r["t"] > t - 86400]


# --------------------------------------------------------------------------- main


def main() -> int:
    cfg = json.loads(CFG_PATH.read_text())
    key = Path(os.path.expanduser(cfg["key_file"])).read_bytes().strip()
    state = load_state()
    hb = collect(cfg)
    hb["acks"] = state["acks"][:20]
    hb["sent_at"] = int(time.time())
    body = json.dumps(hb, sort_keys=True).encode()
    ts, nonce = int(time.time()), wdproto.new_nonce()
    req = urllib.request.Request(cfg["sprite_url"].rstrip("/") + "/v1/heartbeat", data=body, method="POST", headers={
        "Content-Type": "application/json", "X-WD-Ts": str(ts), "X-WD-Nonce": nonce,
        "X-WD-Sig": wdproto.sign_heartbeat(key, ts, nonce, body), "User-Agent": "fly-watchdog-link/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw, sig = r.read(65536), r.headers.get("X-WD-Sig", "")
    except Exception as e:
        log("push-failed", error=type(e).__name__)
        save_state(state)
        return 1
    if not wdproto.verify_orders(key, nonce, sig, raw):
        log("reply-rejected", reason="bad-sig")
        save_state(state)
        return 2
    try:
        orders = json.loads(raw).get("orders", [])
        if not isinstance(orders, list):
            raise ValueError("invalid orders")
    except Exception:
        log("reply-rejected", reason="bad-json")
        save_state(state)
        return 2
    del state["acks"][:len(hb["acks"])]  # delivered
    if orders:
        handle_orders(orders, cfg, state)
    save_state(state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
