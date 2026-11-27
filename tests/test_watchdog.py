import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
for p in ("common", "sprite", "devbox"):
    sys.path.insert(0, str(ROOT / p))

import wdproto  # noqa: E402
import watchdog  # noqa: E402
import watchdog_link  # noqa: E402

KEY = b"k" * 64


class Proto(unittest.TestCase):
    def test_roundtrip_and_domain_separation(self):
        n = wdproto.new_nonce()
        ts = int(time.time())
        sig = wdproto.sign_heartbeat(KEY, ts, n, b"{}")
        self.assertIsNone(wdproto.verify_heartbeat(KEY, str(ts), n, sig, b"{}"))
        self.assertEqual(wdproto.verify_heartbeat(KEY, str(ts), n, sig, b"{ }"), "bad-sig")
        self.assertEqual(wdproto.verify_heartbeat(b"x" * 64, str(ts), n, sig, b"{}"), "bad-sig")
        self.assertEqual(wdproto.verify_heartbeat(KEY, str(ts - 1000), n, sig, b"{}"), "stale-ts")
        self.assertEqual(wdproto.verify_heartbeat(KEY, "abc", n, sig, b"{}"), "bad-ts")
        self.assertEqual(wdproto.verify_heartbeat(KEY, "9" * 100, n, sig, b"{}"), "bad-ts")
        self.assertEqual(wdproto.verify_heartbeat(KEY, str(ts), "zz", sig, b"{}"), "bad-nonce")
        # an order signature is not a heartbeat signature and vice versa
        osig = wdproto.sign_orders(KEY, n, b"{}")
        self.assertNotEqual(osig, sig)
        self.assertTrue(wdproto.verify_orders(KEY, n, osig, b"{}"))
        self.assertFalse(wdproto.verify_orders(KEY, wdproto.new_nonce(), osig, b"{}"))
        self.assertFalse(wdproto.verify_orders(KEY, n, "", b"{}"))

    def test_unit_regex(self):
        for bad in ["../x.service", "a b.service", "x.socket", "-x.service", "x.service;rm", "X.service", ""]:
            self.assertIsNone(wdproto.UNIT_RE.match(bad), bad)
        self.assertTrue(wdproto.UNIT_RE.match("job-supervisor.service"))


def order(unit="job-supervisor.service", **kw):
    t = int(time.time())
    o = {"id": wdproto.new_nonce(), "action": "start_unit", "unit": unit, "issued_at": t, "expires_at": t + 600}
    o.update(kw)
    return o


class Vet(unittest.TestCase):
    def st(self):
        return {"executed": {}, "runs": [], "acks": []}

    def test_allows_whitelisted(self):
        self.assertIsNone(watchdog_link.vet(order(), {}, self.st(), time.time()))

    def test_refusals(self):
        t = time.time()
        s = self.st()
        self.assertEqual(watchdog_link.vet(order("some-other-job.service"), {}, s, t), "unit-not-allowed")
        self.assertEqual(watchdog_link.vet(order(action="stop_unit"), {}, s, t), "action-not-allowed")
        self.assertEqual(watchdog_link.vet(order(action="run", unit="x"), {}, s, t), "action-not-allowed")
        self.assertEqual(watchdog_link.vet(order(expires_at=int(t) - 1), {}, s, t), "expired")
        self.assertEqual(watchdog_link.vet(order(expires_at=int(t) + 99999), {}, s, t), "expired")
        self.assertEqual(watchdog_link.vet(order(id="nope"), {}, s, t), "bad-id")
        self.assertEqual(watchdog_link.vet(order(issued_at=int(t) - 5000), {}, s, t), "bad-issued-at")
        self.assertEqual(watchdog_link.vet(order(issued_at=int(t) + 5000, expires_at=int(t) + 3000), {}, s, t), "bad-issued-at")
        self.assertEqual(watchdog_link.vet(order(issued_at="1"), {}, s, t), "bad-issued-at")
        self.assertEqual(watchdog_link.vet("str", {}, s, t), "malformed")
        # config can narrow but not widen
        self.assertEqual(watchdog_link.vet(order("evil.service"), {"allow_units": ["evil.service"]}, s, t), "unit-not-allowed")
        self.assertEqual(watchdog_link.vet(order("jobs-sync.service"), {"allow_units": ["job-supervisor.service"]}, s, t), "unit-not-allowed")

    def test_replay_and_rate_limits(self):
        t = time.time()
        s = self.st()
        o = order()
        s["executed"][o["id"]] = t
        self.assertEqual(watchdog_link.vet(o, {}, s, t), "replay")
        s = self.st()
        s["runs"] = [{"t": t - 60, "unit": "job-supervisor.service"}]
        self.assertEqual(watchdog_link.vet(order(), {}, s, t), "too-soon")
        self.assertIsNone(watchdog_link.vet(order("jobs-sync.service"), {}, s, t))
        s["runs"] = [{"t": t - 5000 - i, "unit": "jobs-sync.timer"} for i in range(6)]
        self.assertEqual(watchdog_link.vet(order(), {}, s, t), "daily-limit")

    def test_handle_orders_runs_exact_argv(self):
        s = self.st()
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            self.assertNotIn("shell", kw)
            return mock.Mock(returncode=0)

        with tempfile.TemporaryDirectory() as d, mock.patch.object(watchdog_link, "STATE_DIR", Path(d)), \
                mock.patch.object(watchdog_link.subprocess, "run", side_effect=fake_run):
            watchdog_link.handle_orders([order(), order("rm -rf.service"), order("jobs-sync.service")] + [order()] * 5, {}, s)
        self.assertEqual(calls, [["systemctl", "--user", "start", "--no-block", "job-supervisor.service"],
                                 ["systemctl", "--user", "start", "--no-block", "jobs-sync.service"]])
        self.assertEqual(len(s["runs"]), 2)


class Rules(unittest.TestCase):
    def cfg(self):
        return {"kick_units": ["job-supervisor.service", "job-supervisor.timer", "jobs-sync.service"],
                "heartbeat_stale_s": 480, "job_stalled_after_s": 5400}

    def test_heartbeat_checks(self):
        cfg = self.cfg()
        self.assertFalse(watchdog.heartbeat_checks(cfg, None, None)["devbox-heartbeat"][0])
        r = watchdog.heartbeat_checks(cfg, {}, time.time() - 1000)
        self.assertEqual(list(r), ["devbox-heartbeat"])
        self.assertFalse(r["devbox-heartbeat"][0])
        hb = {"checks": {"gateway": {"ok": False, "detail": "HTTP 502"}},
              "jobs": [{"name": "a", "state": "running", "progress_age_s": 99999},
                       {"name": "b", "state": "running", "progress_age_s": 10, "status": "2026 blocked: rewrite guard (x)"},
                       {"name": "c", "state": "running", "progress_age_s": 10}]}
        r = watchdog.heartbeat_checks(cfg, hb, time.time())
        self.assertFalse(r["devbox:gateway"][0])
        self.assertFalse(r["job:a"][0])
        self.assertFalse(r["job:b"][0])
        self.assertIn("rewrite guard", r["job:b"][1])
        self.assertTrue(r["job:c"][0])

    def test_plan_kicks_rules_and_cooldown(self):
        with tempfile.TemporaryDirectory() as d:
            st = watchdog.State(Path(d))
            cfg = self.cfg()
            hb = {"supervisor": {"timer_active": False, "last_run_age_s": 4000},
                  "jobs": [{"name": "a", "state": "running"}], "jobs_index_age_s": 2000}
            ks = watchdog.plan_kicks(cfg, st, hb, time.time())
            self.assertEqual(sorted(k["unit"] for k in ks), ["job-supervisor.service", "job-supervisor.timer", "jobs-sync.service"])
            self.assertEqual(watchdog.plan_kicks(cfg, st, hb, time.time()), [])  # pending + cooldown
            # stale heartbeat -> never kick
            st2 = watchdog.State(Path(d) / "x")
            self.assertEqual(watchdog.plan_kicks(cfg, st2, hb, time.time() - 9999), [])
            # all jobs done -> no supervisor kick
            hb2 = {"supervisor": {"timer_active": True, "last_run_age_s": 99999}, "jobs": [], "jobs_index_age_s": 10}
            self.assertEqual(watchdog.plan_kicks(cfg, watchdog.State(Path(d) / "y"), hb2, time.time()), [])


class Keepalive(unittest.TestCase):
    def test_no_hold_when_loop_dead(self):
        with tempfile.TemporaryDirectory() as d:
            st = watchdog.State(Path(d))
            agent = watchdog.Agent({"interval_s": 10}, KEY, st)
            agent.last_cycle = time.monotonic() - 1000
            with mock.patch.object(watchdog.time, "sleep", side_effect=StopIteration), \
                    mock.patch.object(watchdog.os.path, "exists", return_value=True) as ex, \
                    mock.patch.object(watchdog, "HTTPConnection") as conn:
                with self.assertRaises(StopIteration):
                    watchdog.keepalive_forever(st, agent)
            conn.assert_not_called()
            ex.assert_not_called()


class WakeMode(unittest.TestCase):
    def test_maybe_cycle_respects_gap(self):
        with tempfile.TemporaryDirectory() as d:
            agent = watchdog.Agent({"min_cycle_gap_s": 60, "expect_heartbeat": False}, KEY, watchdog.State(Path(d)))
            agent.last_cycle = time.monotonic() - 100
            with mock.patch.object(agent, "cycle") as c:
                self.assertTrue(agent.maybe_cycle())
                self.assertFalse(agent.maybe_cycle())  # inside the gap
                self.assertEqual(c.call_count, 1)


class EndToEnd(unittest.TestCase):
    """Real HTTP: devbox link -> Sprite handler -> signed orders -> vetted execution."""

    def test_receipts_survive_rejected_reply_and_drain_in_batches(self):
        receipts = [{"id": f"{i:032x}", "result": "dry-run"} for i in range(21)]
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "key").write_bytes(KEY)
            (d / "config").write_text(json.dumps({"sprite_url": "http://example.invalid", "key_file": str(d / "key")}))
            with mock.patch.object(watchdog_link, "CFG_PATH", d / "config"), \
                    mock.patch.object(watchdog_link, "STATE_DIR", d), \
                    mock.patch.object(watchdog_link, "collect", return_value={}), \
                    mock.patch.object(watchdog_link.urllib.request, "urlopen") as send:
                state = watchdog_link.load_state()
                state["acks"] = receipts
                watchdog_link.save_state(state)
                response = send.return_value.__enter__.return_value
                for body, valid, expected in [(b'{}', False, 2), (b'{"orders":{}}', True, 2), (b'{}', True, 0)]:
                    with mock.patch.object(wdproto, "new_nonce", return_value="1" * 32):
                        response.headers = {"X-WD-Sig": wdproto.sign_orders(KEY, "1" * 32, body) if valid else ""}
                        response.read.return_value = body
                        self.assertEqual(watchdog_link.main(), expected)
                    self.assertEqual(watchdog_link.load_state()["acks"], receipts if expected else receipts[20:])
                    self.assertEqual(json.loads(send.call_args.args[0].data)["acks"], receipts[:20])

    def test_full_loop(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            st = watchdog.State(d / "sprite")
            cfg = {"kick_units": ["job-supervisor.service"], "mode": "test"}
            srv = ThreadingHTTPServer(("127.0.0.1", 0), watchdog.make_handler(cfg, KEY, st))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            (d / "key").write_bytes(KEY)
            t = int(time.time())
            st.data["orders"].append({"id": wdproto.new_nonce(), "action": "start_unit", "unit": "job-supervisor.service",
                                      "why": "t", "issued_at": t, "expires_at": t + 600, "state": "queued"})
            link_cfg = {"sprite_url": f"http://127.0.0.1:{srv.server_port}", "key_file": str(d / "key"),
                        "jobs_json": str(d / "missing.json")}
            (d / "link.json").write_text(json.dumps(link_cfg))
            calls = []
            with mock.patch.object(watchdog_link, "CFG_PATH", d / "link.json"), \
                    mock.patch.object(watchdog_link, "STATE_DIR", d / "link"), \
                    mock.patch.object(watchdog_link, "sh", return_value=""), \
                    mock.patch.object(watchdog_link, "execute", side_effect=lambda u: calls.append(u) or "started"):
                self.assertEqual(watchdog_link.main(), 0)
                self.assertEqual(calls, ["job-supervisor.service"])
                self.assertIsNotNone(st.data["heartbeat_at"])
                self.assertEqual(st.data["orders"][0]["state"], "delivered")
                self.assertEqual(watchdog_link.main(), 0)  # second push acks it
                self.assertEqual(st.data["orders"][0]["state"], "acked")
                self.assertEqual(calls, ["job-supervisor.service"])
                # wrong key -> Sprite rejects, nothing executes
                (d / "key").write_bytes(b"z" * 64)
                self.assertEqual(watchdog_link.main(), 1)
            srv.shutdown()
            srv.server_close()

    def test_forged_reply_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "key").write_bytes(KEY)
            (d / "link.json").write_text(json.dumps({"sprite_url": "http://x", "key_file": str(d / "key"), "jobs_json": "/nonexistent"}))
            body = json.dumps({"orders": [order()]}).encode()
            resp = mock.MagicMock()
            resp.__enter__.return_value = resp
            resp.read.return_value = body
            resp.headers = {"X-WD-Sig": wdproto.sign_orders(KEY, "0" * 32, body)}  # signed for another nonce
            ran = []
            with mock.patch.object(watchdog_link, "CFG_PATH", d / "link.json"), \
                    mock.patch.object(watchdog_link, "STATE_DIR", d / "link"), \
                    mock.patch.object(watchdog_link, "sh", return_value=""), \
                    mock.patch.object(watchdog_link.urllib.request, "urlopen", return_value=resp), \
                    mock.patch.object(watchdog_link, "execute", side_effect=lambda u: ran.append(u)):
                self.assertEqual(watchdog_link.main(), 2)
            self.assertEqual(ran, [])

    def test_unauthenticated_requests(self):
        with tempfile.TemporaryDirectory() as d:
            st = watchdog.State(Path(d))
            srv = ThreadingHTTPServer(("127.0.0.1", 0), watchdog.make_handler({}, KEY, st))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            import urllib.error
            import urllib.request
            base = f"http://127.0.0.1:{srv.server_port}"
            for path, data in (("/status", None), ("/v1/heartbeat", b"{}"), ("/anything", None)):
                with self.assertRaises(urllib.error.HTTPError) as e:
                    urllib.request.urlopen(urllib.request.Request(base + path, data=data), timeout=5)
                self.assertIn(e.exception.code, (401, 404))
                e.exception.close()
            self.assertEqual(json.loads(urllib.request.urlopen(base + "/healthz").read()), {"ok": True})
            # replayed valid heartbeat is refused
            ts, n = int(time.time()), wdproto.new_nonce()
            h = {"X-WD-Ts": str(ts), "X-WD-Nonce": n, "X-WD-Sig": wdproto.sign_heartbeat(KEY, ts, n, b"{}")}
            self.assertEqual(urllib.request.urlopen(urllib.request.Request(base + "/v1/heartbeat", data=b"{}", headers=h)).status, 200)
            with self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(urllib.request.Request(base + "/v1/heartbeat", data=b"{}", headers=h))
            self.assertEqual(e.exception.code, 401)
            e.exception.close()
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
