import hashlib
import hmac
import json
import socket
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
import channels


def config():
    return {'webhook_hosts': ['hooks.example.com'], 'alert_channels': [
        dict(id='hook', kind='webhook', url='https://hooks.example.com/event', secret='HOOK_KEY', events=['STALL']),
        dict(id='mail', kind='email', to='you@example.com', sender='alerts@example.com', secret='MAIL_KEY', events=['DOWN'])]}


class ChannelTests(unittest.TestCase):
    def test_job_incident_survives_restart_and_closes_once(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sprite'))
        import watchdog
        cfg = config() | dict(fail_threshold=1)
        cfg['alert_channels'][0]['events'].append('RECOVERED')
        for recovery_jobs in ([dict(name='sample', state='done')], []):
            with self.subTest(recovery_jobs=recovery_jobs), tempfile.TemporaryDirectory() as d:
                st = watchdog.State(Path(d))
                st.data.update(heartbeat_at=watchdog.now(), heartbeat={'jobs': [
                    dict(name='sample', state='running', progress_age_s=6000)]})
                a = watchdog.Agent(cfg, bytes(32), st)
                a.alerter = Mock()
                a.cycle()
                a.cycle()
                self.assertEqual(a.alerter.method_calls, [])
                st = watchdog.State(Path(d))
                a = watchdog.Agent(cfg, bytes(32), st)
                a.alerter = Mock()
                st.data['heartbeat']['jobs'] = recovery_jobs
                a.cycle()
                a.cycle()
                events = [json.loads(x['body']) for x in st.data['delivery_queue']]
                self.assertEqual([x['event'] for x in events], ['STALL', 'RECOVERED'])
                self.assertTrue(events[0]['incident'])
                self.assertEqual(events[0]['incident'], events[1]['incident'])
                self.assertEqual(a.alerter.method_calls, [])

    def test_restart_after_reservation(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sprite'))
        import watchdog
        with tempfile.TemporaryDirectory() as d:
            st = watchdog.State(Path(d))
            r = channels.Registry(config(), st)
            r.enqueue('STALL', 100)
            with self.assertRaises(InterruptedError):
                r.drain(100, Mock(side_effect=InterruptedError))
            loaded = watchdog.State(Path(d))
            item, = loaded.data['delivery_queue']
            self.assertEqual(item['attempts'], 1)
            self.assertEqual(loaded.data['delivery_budget']['hook'], [100])
            r = channels.Registry(config(), loaded)
            send = Mock(return_value=204)
            r.drain(item['due'] - .01, send)
            send.assert_not_called()
            r.drain(item['due'], send)
            r.drain(200, send)
            send.assert_called_once()
            self.assertEqual(loaded.data['delivery_queue'], [])

    def test_expiry_at_24_hours(self):
        self.r.enqueue('STALL', 0)
        self.r.enqueue('STALL', 1)
        send = Mock(return_value=200)
        self.r.drain(86400, send)
        send.assert_called_once()
        self.assertEqual(send.call_args.args[1]['created'], 1)
        self.assertEqual([x['reason'] for x in self.state.data['delivery_dead']], ['expired'])

    def test_overflow_isolation_and_dead_letter_retention(self):
        for t in range(128+257):
            self.r.enqueue('STALL', t)
        self.r.enqueue('DOWN', 385)
        queue = self.state.data['delivery_queue']
        self.assertEqual([x['channel'] for x in queue], ['hook'] * 128 + ['mail'])
        dead = self.state.data['delivery_dead']
        self.assertEqual([x['time'] for x in dead], list(range(129, 385)))
        for x in dead:
            self.assertEqual(set(x), {'id', 'channel', 'attempts', 'time', 'reason'})
            self.assertEqual((x['channel'], x['attempts'], x['reason']), ('hook', 0, 'overflow'))
        # Drain all live items before advancing the clock to isolate retention.
        for t in range(385, 385 + 22*3600, 3600):
            for _ in range(6):
                self.r.drain(t, lambda *_: 204)
        self.assertFalse(queue)
        self.r.drain(129+7*86400, Mock())
        self.assertEqual([x['time'] for x in dead], list(range(130, 385)))

    def test_config_change_or_removal_never_delivers_old_items(self):
        for mode in ('changed', 'removed', 'empty'):
            with self.subTest(mode=mode):
                cfg = config()
                self.state.data = {}
                channels.Registry(cfg, self.state).enqueue('STALL', 100)
                if mode == 'empty':
                    cfg['alert_channels'].clear()
                elif mode == 'removed':
                    cfg['alert_channels'].pop(0)
                else:
                    cfg['alert_channels'][0]['url'] += '/changed'
                send = Mock()
                channels.Registry(cfg, self.state).drain(101, send)
                send.assert_not_called()
                self.assertEqual([x['reason'] for x in self.state.data['delivery_dead']], ['configuration'])
                self.assertFalse(self.state.data['delivery_queue'])

    def setUp(self):
        env = patch.dict(channels.os.environ, {'HOOK_KEY':'example', 'MAIL_KEY':'example'})
        env.start()
        self.addCleanup(env.stop)
        self.state = Mock(data={})
        import threading
        self.state.lock = threading.RLock()
        self.r = channels.Registry(config(), self.state)

    def test_route_signature_and_retry_identity(self):
        self.r.enqueue('STALL', 100)
        first = []
        def deliver(c, item, t):
            first.append((c['id'], item['id'], item['body'], t))
            return 503
        for t in (100, 101, 200, 400):
            self.r.drain(t, deliver)
        self.assertEqual(len(first), 3)
        self.assertEqual(len(set(x[:3] for x in first)), 1)
        channel, uid, body, t = first[0]
        self.assertEqual(channel, 'hook')
        self.assertEqual(json.loads(body)['event'], 'STALL')
        key = bytes(range(32))
        expected = hmac.new(key, f'v1\n{t}\n{uid}\n{body}'.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(channels.headers(key, uid, t, body.encode())['X-Watchdog-Signature'], 'v1='+expected)
        self.assertEqual(len(self.state.data['delivery_dead']), 1)

    def test_rolling_budget_restart_and_isolation(self):
        for i in range(7): self.r.enqueue('DOWN', 100)
        self.r.enqueue('STALL', 100)
        send = Mock(return_value=204)
        for _ in range(8): self.r.drain(100, send)
        self.assertEqual(send.call_count, 7)
        self.r = channels.Registry(config(), self.state)
        self.r.drain(3699, send)
        self.assertEqual(send.call_count, 7)
        self.r.drain(3700, send)
        self.assertEqual(send.call_count, 8)

    def test_redirect_terminal(self):
        self.r.enqueue('STALL', 100)
        deliver = Mock(return_value=302)
        self.r.drain(100, deliver)
        self.r.drain(500, deliver)
        self.assertEqual(deliver.call_count, 1)
        self.assertNotIn('orders', self.state.data)

    def test_checked_peer_and_response_is_status_only(self):
        addr = ('93.184.216.34', 443)
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', addr)]
        with patch.object(socket, 'getaddrinfo', return_value=answer) as dns, patch.object(socket, 'socket') as sock, patch.object(channels.ssl, 'create_default_context') as context, patch.object(channels.http.client, 'HTTPSConnection') as connection:
            response = connection.return_value.__enter__.return_value.getresponse.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b'{"action":"start_unit"}'
            self.assertEqual(channels.post('hooks.example.com', '/event', b'{}', {}), 200)
            dns.assert_called_once()
            raw = sock.return_value.__enter__.return_value
            raw.connect.assert_called_once_with(addr)
            context.return_value.wrap_socket.assert_called_once_with(raw, server_hostname='hooks.example.com')
            response.read.assert_not_called()

    def test_agent_transition_persists_without_legacy_send(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sprite'))
        import watchdog
        cfg = config() | dict(fail_threshold=1, expect_heartbeat=True)
        with tempfile.TemporaryDirectory() as d:
            st = watchdog.State(Path(d))
            agent = watchdog.Agent(cfg, bytes(32), st)
            agent.alerter = Mock()
            agent.cycle()
            agent.cycle()
            self.assertFalse(agent.alerter.method_calls)
            saved = watchdog.State(Path(d))
            self.assertEqual([item['channel'] for item in saved.data['delivery_queue']], ['mail'])
            self.assertEqual(saved.data['orders'], [])
            incident = json.loads(saved.data['delivery_queue'][0]['body'])['incident']
            agent.channels.channels['mail']['events'].append('RECOVERED')
            st.data.update(heartbeat={}, heartbeat_at=watchdog.now())
            agent.cycle()
            recovery = json.loads(st.data['delivery_queue'][-1]['body'])
            self.assertEqual((recovery['event'], recovery['incident']), ('RECOVERED',incident))

    def test_policy(self):
        for url in ['http://hooks.example.com/', 'https://hooks.example.com:444/', 'https://bad.example.com/', 'https://user@hooks.example.com/', 'https://127.0.0.1/']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                channels.destination(url, ['hooks.example.com'])
        answers = [(socket.AF_INET, 1, 6, '', (str(ip), 443)) for ip in ('93.184.216.34', '127.0.0.1')]
        with self.assertRaises(ValueError): channels.checked(answers)

    def test_vector_and_tampering(self):
        uid = '00000000-0000-4000-8000-000000000001'
        expected = 'v1=54d37dee61e75f48609e4d7416a4e96cb4938da3750dd2e5aa10e1fcd93042ac'
        for body, valid in [(b'{}', True), (b'{ }', False)]:
            sig = channels.headers(bytes(range(32)), uid, 100, body)['X-Watchdog-Signature']
            self.assertEqual(hmac.compare_digest(expected, sig), valid)

    def test_invalid_registration(self):
        for change in [dict(kind='unknown'), dict(id='hook'), dict(secret='HOOK_KEY'), dict(secret='BAD'), dict(secret='MAIL_MISSING'), dict(events=['UNKNOWN'])]:
            cfg = config()
            cfg['alert_channels'][1].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): channels.Registry(cfg, self.state)
        cfg = config()
        cfg['alert_channels'].append(cfg['alert_channels'][0] | dict(id='other',secret='HOOK_OTHER'))
        with patch.dict(channels.os.environ, {'HOOK_OTHER':'example'}), self.assertRaises(ValueError): channels.Registry(cfg, self.state)

    def test_fanout_and_mail_transport(self):
        cfg = config()
        cfg['alert_channels'][0]['events'] = ['DOWN']
        r = channels.Registry(cfg, self.state)
        r.enqueue('DOWN', 10)
        items = self.state.data['delivery_queue']
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]['body'], items[1]['body'])
        self.assertNotEqual(items[0]['id'], items[1]['id'])
        with patch.object(channels, 'post', return_value=202) as post:
            self.assertEqual(channels.send_one(r.channels['mail'], items[1], 10), 202)
            self.assertEqual(post.call_args.args[:2], ('api.resend.com', '/emails'))
        with patch.object(channels.subprocess,'run',side_effect=channels.subprocess.TimeoutExpired('child',5)) as child:
            self.assertEqual(channels.deliver(r.channels['mail'], items[1],10), 0)
            self.assertEqual(child.call_args.kwargs['timeout'], 5)

    def test_real_restart_concurrent_reservations(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sprite'))
        import watchdog
        with tempfile.TemporaryDirectory() as d:
            st = watchdog.State(Path(d))
            cfg = config() | dict(fail_threshold=1)
            a = watchdog.Agent(cfg, bytes(32), st)
            a.cycle()
            for _ in range(7): a.channels.enqueue('DOWN', watchdog.now())
            send = Mock(return_value=200)
            def drain(_): a.channels.drain(send=send)
            with ThreadPoolExecutor(4) as pool: list(pool.map(drain, range(40)))
            for _ in range(8): drain(None)
            self.assertEqual(send.call_count, 6)
            loaded = watchdog.State(Path(d))
            channels.Registry(cfg, loaded).drain(send=send)
            self.assertEqual(send.call_count, 6)

    def test_empty_vs_absent(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sprite'))
        import watchdog
        for cfg, enabled in [({}, False), ({'alert_channels': []}, True)]:
            with tempfile.TemporaryDirectory() as d:
                a = watchdog.Agent(cfg | dict(fail_threshold=1), bytes(32), watchdog.State(Path(d)))
                a.alerter = Mock()
                a.cycle()
                self.assertEqual(a.channels is not None, enabled)
                self.assertEqual(bool(a.alerter.method_calls), not enabled)
