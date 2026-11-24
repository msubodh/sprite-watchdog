#!/usr/bin/env python3
"""Demo-only stand-ins: three fake web services plus a fake 'home server' that pushes
signed heartbeats with fake jobs. Nothing here touches a real system.

  POST /break/<svc>   make a fake service return 503
  POST /fix/<svc>     make it healthy again
  POST /stall         make the fake job scheduler look stuck (triggers a kick)
Fake services: /svc/shop, /svc/blog, /svc/api   (all on 127.0.0.1:9000)
"""
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import wdproto  # noqa: E402

BROKEN: set[str] = set()
STALLED = {"on": False, "kicked_at": None}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _j(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        svc = self.path.removeprefix("/svc/")
        if self.path.startswith("/svc/") and svc in ("shop", "blog", "api"):
            return self._j(503, {"ok": False}) if svc in BROKEN else self._j(200, {"ok": True, "service": svc})
        self._j(404, {})

    def do_POST(self):
        p = self.path.strip("/").split("/")
        if p[0] == "break" and len(p) == 2:
            BROKEN.add(p[1])
        elif p[0] == "fix" and len(p) == 2:
            BROKEN.discard(p[1])
        elif p[0] == "stall":
            STALLED["on"] = True
        self._j(200, {"broken": sorted(BROKEN), "stalled": STALLED["on"]})


def heartbeats(sprite_url: str, key: bytes) -> None:
    acks = []
    while True:
        t = time.time()
        hb = {"host": "demo-home-server",
              "checks": {"backup-disk": {"ok": True, "detail": "62% used"}, "vpn": {"ok": True, "detail": "active"}},
              "supervisor": {"timer_active": not STALLED["on"], "last_run_age_s": 7200 if STALLED["on"] else 120},
              "jobs": [{"name": "nightly-build", "state": "running", "progress_age_s": 300, "status": ""},
                       {"name": "photo-sync", "state": "running", "progress_age_s": 9000 if STALLED["on"] else 60, "status": ""}],
              "jobs_index_age_s": 60, "acks": acks, "sent_at": int(t)}
        body = json.dumps(hb, sort_keys=True).encode()
        n = wdproto.new_nonce()
        req = urllib.request.Request(sprite_url + "/v1/heartbeat", data=body, method="POST", headers={
            "Content-Type": "application/json", "X-WD-Ts": str(int(t)), "X-WD-Nonce": n,
            "X-WD-Sig": wdproto.sign_heartbeat(key, int(t), n, body)})
        acks = []
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw, sig = r.read(), r.headers.get("X-WD-Sig", "")
            if wdproto.verify_orders(key, n, sig, raw):
                for o in json.loads(raw)["orders"]:
                    print(f"[fake home server] verified kick request: start {o['unit']} -> pretending to restart the scheduler", flush=True)
                    STALLED["on"] = False
                    acks.append({"id": o["id"], "result": "started (demo)"})
        except Exception as e:
            print("[fake home server] push failed:", type(e).__name__, flush=True)
        time.sleep(int(os.environ.get("DEMO_HB_S", "20")))


if __name__ == "__main__":
    key = Path(os.environ["WD_KEY_FILE"]).read_bytes().strip()
    threading.Thread(target=heartbeats, args=(os.environ.get("WD_SPRITE_URL", "http://127.0.0.1:8080"), key), daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 9000), H).serve_forever()
