import hashlib
import hmac
import json
import socket
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
import channels


def config():
    return {'webhook_hosts': ['hooks.example.com'], 'alert_channels': [
        dict(id='hook', kind='webhook', url='https://hooks.example.com/event', secret='HOOK_KEY', events=['STALL']),
        dict(id='mail', kind='email', to='you@example.com', sender='alerts@example.com', secret='MAIL_KEY', events=['DOWN'])]}


class ChannelTests(unittest.TestCase):
    def setUp(self):
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

    def test_policy(self):
        for url in ['http://hooks.example.com/', 'https://hooks.example.com:444/', 'https://bad.example.com/', 'https://user@hooks.example.com/', 'https://127.0.0.1/']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                channels.destination(url, ['hooks.example.com'])
        answers = [(socket.AF_INET, 1, 6, '', (str(ip), 443)) for ip in ('93.184.216.34', '127.0.0.1')]
        with self.assertRaises(ValueError): channels.checked(answers)
