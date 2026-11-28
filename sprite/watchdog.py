#!/usr/bin/env python3
"""fly-watchdog: an outside-in watchdog agent that lives on a Fly.io Sprite.

Loop (every `interval_s`):
  1. Probe public health endpoints (HTTP status + optional JSON field check).
  2. Read the latest signed heartbeat the devbox pushed to us (devbox -> Sprite,
     outbound from the devbox; nothing on the devbox is exposed to the internet).
  3. Decide, with fixed deterministic rules, whether anything is DOWN, RECOVERED,
     STALLED, or whether a narrowly whitelisted "kick" should be queued.
  4. Alert by email through a Sprites connector (Resend). The Sprite never holds
     the Resend API key; the connector gateway attaches it.
  5. Optionally ask an LLM (Cloudflare Workers AI, through a custom-API connector)
     for a two-sentence plain-English summary. The model never decides actions.

Kicks are only ever *requests*: they ride back to the devbox in the signed reply
to its own heartbeat. The devbox re-checks every request against its own local
allowlist and rate limits before running `systemctl --user start <unit>`.

Standard library only. Python 3.11+.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import wdproto  # noqa: E402
from channels import Registry

MAX_BODY = 64 * 1024
MAX_NONCES = 10_000
UA = "fly-watchdog/1.0 (+outside-in health checks)"


def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now() if ts is None else ts))


# --------------------------------------------------------------------------- state


class State:
    """Mutable state, persisted to JSON; events are append-only JSONL."""

    def __init__(self, state_dir: Path):
        self.dir = state_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "state.json"
        self.events_path = self.dir / "events.jsonl"
        self.lock = threading.RLock()
        self.data = {
            "checks": {},  # name -> {status, fails, since, detail, last}
            "heartbeat": None,  # last verified heartbeat payload
            "heartbeat_at": None,
            "orders": [],  # queued/delivered kick requests
            "last_kick": {},  # unit -> ts
            "suppressed": 0,
        }
        self.nonces: OrderedDict[str, float] = OrderedDict()
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text()))
            except (OSError, ValueError):
                pass

    def save(self) -> None:
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.touch(mode=0o600, exist_ok=True)
            tmp.chmod(0o600)
            tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True))
            os.replace(tmp, self.path)

    def event(self, kind: str, **kw) -> None:
        rec = {"at": iso(), "kind": kind, **kw}
        with self.lock, open(self.events_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        print(json.dumps(rec, sort_keys=True), flush=True)

    def seen_nonce(self, nonce: str) -> bool:
        with self.lock:
            t = now()
            while self.nonces and next(iter(self.nonces.values())) < t - 2 * wdproto.MAX_SKEW_S:
                self.nonces.popitem(last=False)
            if nonce in self.nonces:
                return True
            while len(self.nonces) >= MAX_NONCES:  # belt and braces; only signed requests get here
                self.nonces.popitem(last=False)
            self.nonces[nonce] = t
            return False


# --------------------------------------------------------------------------- probes


def http_probe(t: dict) -> tuple[bool, str]:
    req = urllib.request.Request(t["url"], headers={"User-Agent": UA, "Accept": "application/json"})
    want = t.get("expect_status", 200)
    try:
        with urllib.request.urlopen(req, timeout=t.get("timeout_s", 15)) as r:
            status, raw = r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        status, raw = e.code, b""
    except Exception as e:  # network error, TLS, timeout
        return False, f"unreachable ({type(e).__name__})"
    if status != want:
        return False, f"HTTP {status} (expected {want})"
    jf = t.get("json_field")
    if jf:
        try:
            cur = json.loads(raw)
            for part in jf["path"].split("."):
                cur = cur[part]
        except Exception:
            return False, f"HTTP {status}, field {jf['path']} missing"
        if "equals" in jf and cur != jf["equals"]:
            return False, f"{jf['path']}={cur!r} (expected {jf['equals']!r})"
        if "not_in" in jf and cur in jf["not_in"]:
            return False, f"{jf['path']}={cur!r}"
    return True, f"HTTP {status}"


# --------------------------------------------------------------------------- connectors


def gateway_post(url: str, payload: dict, timeout: int = 20) -> tuple[int, bytes]:
    """Call a Sprites connector gateway URL. No Authorization header: the gateway
    identifies this Sprite and attaches the stored credential itself."""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4096)
    except urllib.error.HTTPError as e:
        return e.code, e.read(512)
    except Exception as e:
        return 0, type(e).__name__.encode()


class Alerter:
    def __init__(self, cfg: dict, st: State):
        self.cfg, self.st = cfg.get("alerts", {}), st
        self.llm = cfg.get("llm", {})
        self.demo = cfg.get("mode") == "demo"
        self.sent: list[float] = []  # monotonic timestamps: immune to wall-clock jumps

    def summarize(self, lines: list[str]) -> str | None:
        url = self.llm.get("gateway_url")
        if not url:
            return None
        prompt = (
            "You write two short plain-English sentences for an on-call email. "
            "Say what is wrong and what the watchdog already did. Do not invent facts. "
            "Facts:\n" + "\n".join(lines)
        )
        code, raw = gateway_post(
            url.rstrip("/") + "/run/" + self.llm.get("model", "@cf/meta/llama-3.1-8b-instruct"),
            {"messages": [{"role": "user", "content": prompt}], "max_tokens": 120},
        )
        if code != 200:
            self.st.event("llm-error", status=code)
            return None
        try:
            return json.loads(raw)["result"]["response"].strip()[:600]
        except Exception:
            return None

    def send(self, subject: str, lines: list[str]) -> bool:
        with self.st.lock:
            t = time.monotonic()
            self.sent = [x for x in self.sent if x > t - 3600]
            if len(self.sent) >= self.cfg.get("max_per_hour", 6):
                self.st.data["suppressed"] += 1
                self.st.event("alert-suppressed", subject=subject)
                return False
            self.sent.append(t)
        summary = self.summarize(lines)
        prefix = "[DEMO] " if self.demo else ""
        body = ""
        if summary:
            body += summary + "\n\n(Summary written by Workers AI from the facts below.)\n\n"
        body += "\n".join(f"- {line}" for line in lines)
        body += f"\n\nfly-watchdog on a Fly.io Sprite, {iso()}.\n"
        url = self.cfg.get("resend_gateway_url")
        if not url:
            self.st.event("alert-console", subject=prefix + subject, lines=lines, summary=summary)
            return True
        code, _ = gateway_post(url.rstrip("/") + "/emails", {
            "from": self.cfg["from"], "to": [self.cfg["to"]],
            "subject": prefix + subject, "text": body,
        })
        self.st.event("alert-sent" if code in (200, 201) else "alert-failed", subject=prefix + subject, status=code)
        return code in (200, 201)


# --------------------------------------------------------------------------- rules


def heartbeat_checks(cfg: dict, hb: dict | None, hb_at: float | None) -> dict[str, tuple[bool, str]]:
    """Turn the last verified heartbeat into named check results (deterministic)."""
    out: dict[str, tuple[bool, str]] = {}
    stale_s = cfg.get("heartbeat_stale_s", 480)
    age = None if hb_at is None else now() - hb_at
    if age is None:
        out["devbox-heartbeat"] = (False, "no heartbeat received yet")
        return out
    if age > stale_s:
        out["devbox-heartbeat"] = (False, f"silent for {int(age // 60)} min")
        return out  # the rest of the heartbeat is too old to trust
    out["devbox-heartbeat"] = (True, f"last seen {int(age)} s ago")
    for name, c in sorted((hb.get("checks") or {}).items()):
        if isinstance(c, dict):
            out[f"devbox:{name}"[:64]] = (bool(c.get("ok")), str(c.get("detail", ""))[:160])
    stalled_after = cfg.get("job_stalled_after_s", 5400)
    for j in hb.get("jobs") or []:
        if not isinstance(j, dict):
            continue
        name = str(j.get("name", "?"))[:48]
        status = str(j.get("status", ""))[:160]
        if status.split(" ", 1)[-1].startswith("blocked"):
            out[f"job:{name}"] = (False, f"blocked: {status.split('blocked', 1)[1].strip(': ')[:120]}")
        elif j.get("state") not in ("done",) and isinstance(j.get("progress_age_s"), (int, float)) and j["progress_age_s"] > stalled_after:
            out[f"job:{name}"] = (False, f"no progress for {int(j['progress_age_s'] // 60)} min (state {j.get('state')})")
        else:
            out[f"job:{name}"] = (True, str(j.get("state", "")))
    return out


def plan_kicks(cfg: dict, st: State, hb: dict | None, hb_at: float | None) -> list[dict]:
    """Fixed rules -> kick requests. Units must be on the Sprite's list here AND on
    the devbox's own allowlist; the devbox is the one that decides."""
    if not hb or hb_at is None or now() - hb_at > cfg.get("heartbeat_stale_s", 480):
        return []
    allowed = set(cfg.get("kick_units", []))
    cooldown = cfg.get("kick_cooldown_s", 1800)
    want: list[tuple[str, str]] = []
    sup = hb.get("supervisor") or {}
    open_jobs = [j for j in hb.get("jobs") or [] if isinstance(j, dict) and j.get("state") != "done"]
    if open_jobs and (sup.get("timer_active") is False or (sup.get("last_run_age_s") or 0) > cfg.get("supervisor_stale_s", 1800)):
        want.append(("job-supervisor.service", "supervisor has not run recently while jobs are open"))
        if sup.get("timer_active") is False:
            want.append(("job-supervisor.timer", "supervisor timer is not active"))
    idx_age = hb.get("jobs_index_age_s")
    if isinstance(idx_age, (int, float)) and idx_age > cfg.get("jobs_index_stale_s", 900):
        want.append(("jobs-sync.service", f"job index is {int(idx_age // 60)} min old"))
    orders = []
    t = now()
    with st.lock:
        pending_units = set()
        for o in st.data["orders"]:
            if o["state"] in ("queued", "delivered"):
                if o["expires_at"] < t:
                    o["state"] = "expired"
                else:
                    pending_units.add(o["unit"])
        for unit, why in want:
            if unit not in allowed or not wdproto.UNIT_RE.match(unit) or unit in pending_units:
                continue
            if t - st.data["last_kick"].get(unit, 0) < cooldown:
                continue
            o = {"id": wdproto.new_nonce(), "action": "start_unit", "unit": unit, "why": why[:160],
                 "issued_at": int(t), "expires_at": int(t + 600), "state": "queued"}
            st.data["orders"].append(o)
            st.data["last_kick"][unit] = t
            orders.append(o)
        st.data["orders"] = st.data["orders"][-50:]
    return orders


# --------------------------------------------------------------------------- agent loop


class Agent:
    def __init__(self, cfg: dict, key: bytes, st: State):
        self.cfg, self.key, self.st = cfg, key, st
        self.alerter = Alerter(cfg, st)
        self.channels = Registry(cfg, st) if 'alert_channels' in cfg else None
        self.need_fails = cfg.get("fail_threshold", 2)
        self.last_cycle = time.monotonic()
        self.cycle_lock = threading.Lock()
        self.min_gap_s = cfg.get("min_cycle_gap_s", 60)

    def cycle(self) -> None:
        results: dict[str, tuple[bool, str]] = {}
        for t in self.cfg.get("targets", []):
            results[t["name"]] = http_probe(t)
        with self.st.lock:
            hb, hb_at = self.st.data["heartbeat"], self.st.data["heartbeat_at"]
        if self.cfg.get("expect_heartbeat", True):
            results.update(heartbeat_checks(self.cfg, hb, hb_at))
        kicks = plan_kicks(self.cfg, self.st, hb, hb_at)
        down, up = [], []
        with self.st.lock:
            checks = self.st.data["checks"]
            for name, (ok, detail) in results.items():
                c = checks.setdefault(name, {"status": "up", "fails": 0, "since": iso()})
                c["detail"], c["last"] = detail, iso()
                if ok:
                    if c["status"] == "down":
                        up.append(f"RECOVERED {name}: {detail} (was down since {c['since']})")
                        if self.channels:
                            self.channels.enqueue('RECOVERED', now(), name)
                        c["status"], c["since"] = "up", iso()
                    c["fails"] = 0
                else:
                    c["fails"] += 1
                    if c["status"] != "down" and c["fails"] >= self.need_fails:
                        c["status"], c["since"] = "down", iso()
                        down.append(f"DOWN {name}: {detail}")
                        if self.channels:
                            self.channels.enqueue('STALL' if name.startswith('job:') else 'DOWN', now(), name)
            # checks that disappeared (e.g. a job finished) are dropped quietly
            for gone in [n for n in checks if n not in results]:
                if self.channels and checks[gone]['status'] == 'down':
                    self.channels.enqueue('RECOVERED', now(), gone)
                del checks[gone]
            if self.channels:
                for order in kicks:
                    self.channels.enqueue('KICK', now(), order['unit'])
            self.st.save()
        for k in kicks:
            self.st.event("kick-queued", unit=k["unit"], why=k["why"], order=k["id"][:8])
        lines = down + up + [f"KICK requested: start {k['unit']} ({k['why']}); the devbox checks its own allowlist first" for k in kicks]
        if down or up:
            subject = f"{len(down)} down, {len(up)} recovered" if down else f"{len(up)} recovered"
            self.st.event("transition", down=down, up=up)
            if not self.channels:
                self.alerter.send(f"Watchdog: {subject}", lines)
        elif kicks and not self.channels:
            self.alerter.send("Watchdog: requested a restart kick", lines)

    def maybe_cycle(self) -> bool:
        """Run one cycle unless one ran recently or is running (heartbeat-wake mode)."""
        if time.monotonic() - self.last_cycle < self.min_gap_s or not self.cycle_lock.acquire(blocking=False):
            return False
        try:
            self.cycle()
        except Exception as e:
            self.st.event("cycle-error", error=type(e).__name__, detail=str(e)[:200])
        finally:
            self.last_cycle = time.monotonic()
            self.cycle_lock.release()
        return True

    def run_forever(self) -> None:
        interval = self.cfg.get("interval_s", 180)
        self.st.event("agent-start", mode=self.cfg.get("mode", "prod"), interval_s=interval)
        if self.cfg.get("startup_email") and not self.channels:
            self.alerter.send("Watchdog online", [f"Started on a Fly.io Sprite; checking {len(self.cfg.get('targets', []))} endpoints every {interval} s plus the devbox heartbeat."])
        while True:
            t0 = now()
            with self.cycle_lock:
                try:
                    self.cycle()
                except Exception as e:  # never die; log and continue
                    self.st.event("cycle-error", error=type(e).__name__, detail=str(e)[:200])
                self.last_cycle = time.monotonic()
            time.sleep(max(5, interval - (now() - t0)))


# --------------------------------------------------------------------------- keepalive


def keepalive_forever(st: State, agent: "Agent", expire: str = "5m") -> None:
    """Hold the Sprite awake with the Tasks API (5 min expiry refreshed every 60 s),
    so the probe loop keeps running even when nothing calls the URL. If this
    process dies, the task expires and the Sprite is free to sleep (fail-cheap)."""
    sock = "/.sprite/api.sock"
    while True:
        # Only hold the Sprite awake while the probe loop is demonstrably alive.
        alive = time.monotonic() - agent.last_cycle < 3 * agent.cfg.get("interval_s", 180) + 60
        if not alive:
            st.event("keepalive-skipped", reason="agent loop not cycling")
        if alive and os.path.exists(sock):
            try:
                conn = HTTPConnection("sprite")
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect(sock)
                conn.sock = s
                conn.request("PUT", "/v1/tasks/fly-watchdog", body=json.dumps({"expire": expire}),
                             headers={"Content-Type": "application/json", "Host": "sprite"})
                r = conn.getresponse()
                r.read()
                if r.status >= 300:
                    st.event("keepalive-error", status=r.status)
                conn.close()
            except OSError as e:
                st.event("keepalive-error", error=type(e).__name__)
        time.sleep(60)


# --------------------------------------------------------------------------- HTTP

STATUS_HTML = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width">
<title>fly-watchdog</title><style>body{font:16px system-ui;margin:2rem;background:#0b1020;color:#e8ecf8}
h1{font-size:1.4rem}.c{display:flex;gap:.6rem;align-items:center;padding:.45rem .7rem;margin:.3rem 0;border-radius:8px;background:#151c33}
.d{width:.8rem;height:.8rem;border-radius:50%}.up{background:#3ddc84}.down{background:#ff5470}small{color:#9aa4c4}</style>
<h1>fly-watchdog <small id=m></small></h1><div id=c></div><h2 style="font-size:1.1rem">Recent kicks</h2><div id=k></div>
<script>const e=x=>String(x??'').replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');async function r(){const s=await (await fetch('/status')).json();m.textContent=s.mode+' mode, '+s.at;
c.innerHTML=Object.entries(s.checks).map(([n,v])=>`<div class=c><span class="d ${e(v.status)}"></span><b>${e(n)}</b><small>${e(v.detail)}</small></div>`).join('');
k.innerHTML=(s.recent_kicks||[]).map(o=>`<div class=c>start ${e(o.unit)} <small>${e(o.why)} [${e(o.state)}${o.result?': '+e(o.result):''}]</small></div>`).join('')||'<small>none</small>'}
r();setInterval(r,3000)</script>"""


def make_handler(cfg: dict, key: bytes, st: State, agent: "Agent | None" = None):
    public_status = cfg.get("public_status", False)

    class H(BaseHTTPRequestHandler):
        server_version = "fly-watchdog"
        sys_version = ""

        def log_message(self, fmt, *args):  # keep logs quiet and secret-free
            pass

        def _send(self, code: int, obj: dict, extra: dict | None = None) -> None:
            body = json.dumps(obj, sort_keys=True).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, {"ok": True})
            if self.path == "/" and public_status:
                body = STATUS_HTML.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return None
            if self.path == "/status" and public_status:
                with st.lock:
                    checks = {n: {k: c.get(k) for k in ("status", "detail", "since")} for n, c in st.data["checks"].items()}
                    orders = [{k: o.get(k) for k in ("unit", "why", "state", "result")} for o in st.data["orders"][-10:]]
                return self._send(200, {"mode": cfg.get("mode"), "checks": checks, "recent_kicks": orders, "at": iso()})
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/v1/heartbeat":
                return self._send(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                return self._send(413, {"error": "too large"})
            body = self.rfile.read(n)
            nonce = self.headers.get("X-WD-Nonce", "")
            why = wdproto.verify_heartbeat(key, self.headers.get("X-WD-Ts", ""), nonce, self.headers.get("X-WD-Sig", ""), body)
            if why is None and st.seen_nonce(nonce):
                why = "replay"
            if why:
                st.event("heartbeat-rejected", reason=why)
                return self._send(401, {"error": "unauthorized"})
            try:
                hb = json.loads(body)
                assert isinstance(hb, dict)
            except Exception:
                return self._send(400, {"error": "bad json"})
            with st.lock:
                st.data["heartbeat"], st.data["heartbeat_at"] = hb, now()
                by_id = {o["id"]: o for o in st.data["orders"]}
                for a in hb.get("acks") or []:
                    o = by_id.get(str(a.get("id", ""))) if isinstance(a, dict) else None
                    if o and o["state"] == "delivered":
                        o["state"], o["result"] = "acked", str(a.get("result", ""))[:80]
                        st.event("kick-acked", unit=o["unit"], result=o["result"])
                t = now()
                out = []
                for o in st.data["orders"]:
                    if o["state"] == "queued":
                        if o["expires_at"] < t:
                            o["state"] = "expired"
                            continue
                        o["state"] = "delivered"
                        out.append({k: o[k] for k in ("id", "action", "unit", "issued_at", "expires_at")})
                st.save()
            resp = json.dumps({"orders": out}, sort_keys=True).encode()
            sig = wdproto.sign_orders(key, nonce, resp)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.send_header("X-WD-Sig", sig)
            self.end_headers()
            self.wfile.write(resp)
            if (agent is not None and cfg.get("cycle_on_heartbeat", False)
                    and time.monotonic() - agent.last_cycle >= agent.min_gap_s and not agent.cycle_lock.locked()):
                # heartbeat-wake mode: the devbox push is what wakes the Sprite, so check now
                threading.Thread(target=agent.maybe_cycle, daemon=True).start()

    return H


def main() -> None:
    cfg_path = Path(os.environ.get("WD_CONFIG", "/home/sprite/fly-watchdog/config.json"))
    cfg = json.loads(cfg_path.read_text())
    key_file = Path(os.environ.get("WD_KEY_FILE", "/home/sprite/.config/fly-watchdog/hmac.key"))
    key = key_file.read_bytes().strip()
    if len(key) < 32:
        sys.exit("hmac key too short")
    st = State(Path(os.environ.get("WD_STATE_DIR", "/home/sprite/fly-watchdog/state")))
    agent = Agent(cfg, key, st)
    if agent.channels and cfg.get('mode') != 'demo':
        threading.Thread(target=agent.channels.run, daemon=True).start()
    threading.Thread(target=agent.run_forever, daemon=True).start()
    if cfg.get("keepalive", True):
        threading.Thread(target=keepalive_forever, args=(st, agent), daemon=True).start()
    port = int(os.environ.get("PORT", cfg.get("port", 8080)))
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(cfg, key, st, agent)).serve_forever()


if __name__ == "__main__":
    main()
