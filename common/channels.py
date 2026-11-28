"""Registered notification outbox. No access to the heartbeat action protocol."""
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or not re.fullmatch(
        r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value
    ):
        raise ValueError('invalid hostname')
    return value


def destination(url, hosts):
    if not isinstance(url, str) or not re.fullmatch(r'https://[A-Za-z0-9.:/-]+(?:[A-Za-z0-9._~/-]*)', url):
        raise ValueError('invalid webhook URL')
    parts = urlsplit(url)
    host = hostname(parts.hostname)
    if host not in hosts or parts.netloc not in (host, host + ':443'):
        raise ValueError('destination not allowed')
    return host, parts.path or '/'


def checked(answers):
    if not answers:
        raise ValueError('empty DNS answer')
    for family, _, _, _, address in answers:
        ip = ipaddress.ip_address(address[0])
        if (family not in (socket.AF_INET, socket.AF_INET6) or not ip.is_global or
                ip.is_multicast or ip.is_reserved or getattr(ip, 'ipv4_mapped', None) or
                getattr(ip, 'sixtofour', None) or getattr(ip, 'teredo', None) or
                ip == ipaddress.ip_address('168.63.129.16') or
                (ip.version == 6 and ip not in ipaddress.ip_network('2000::/3'))):
            raise ValueError('non-public DNS answer')
    return answers[0]


def headers(key, uid, timestamp, body):
    signed = f'v1\n{timestamp}\n{uid}\n'.encode() + body
    return {'X-Watchdog-Signature': 'v1=' + hmac.new(key, signed, hashlib.sha256).hexdigest(),
            'X-Watchdog-Timestamp': str(timestamp), 'X-Watchdog-Delivery': uid}


def post(host, path, body, fields):
    family, kind, protocol, _, addr = checked(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
    with socket.socket(family, kind, protocol) as raw:
        raw.settimeout(4)
        raw.connect(addr)
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
            with http.client.HTTPSConnection(host) as conn:
                conn.sock = tls
                conn.request('POST', path, body, {'Content-Type': 'application/json', **fields})
                with conn.getresponse() as response:
                    return response.status  # Never read the body or follow Location.


def send_one(c, item, timestamp):
    key = os.environ.get(c['secret'])
    if not key:
        return 400
    body = item['body'].encode()
    if c['kind'] == 'webhook':
        host, path = destination(c['url'], [urlsplit(c['url']).hostname])
        return post(host, path, body, headers(key.encode(), item['id'], timestamp, body))
    payload = {'from': c['sender'], 'to': [c['to']], 'subject': 'Watchdog notification', 'text': item['body']}
    return post('api.resend.com', '/emails', json.dumps(payload).encode(),
                {'Authorization': 'Bearer ' + key, 'Idempotency-Key': item['id']})


def deliver(c, item, timestamp):
    # OS process deadline also covers blocking libc DNS and slow response headers.
    try:
        p = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve())],
                           input=json.dumps([c, item, timestamp]), text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True)
        return int(p.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


class Registry:
    def __init__(self, cfg, state):
        hosts = cfg.get('webhook_hosts', [])
        entries = cfg['alert_channels']
        if not isinstance(hosts, list) or not isinstance(entries, list) or len(entries) > 32:
            raise ValueError('invalid registry')
        hosts = {hostname(x) for x in hosts}
        self.channels = {}
        self.bindings = {}
        seen = set()
        keys = set()
        for c in entries:
            email = c.get('kind') == 'email'
            fields = {'id', 'events', 'kind', 'secret'} | ({'sender', 'to'} if email else {'url'})
            if (set(c) != fields or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', c['id']) or
                    c['id'] in self.channels or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', c['secret']) or
                    not isinstance(c['events'], list) or not c['events'] or
                    set(c['events']) - {'DOWN', 'RECOVERED', 'STALL', 'KICK'} or
                    len(set(c['events'])) != len(c['events'])):
                raise ValueError('invalid channel')
            if email:
                if not all(re.fullmatch(r'[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', c[k]) for k in ('to', 'sender')):
                    raise ValueError('invalid email address')
                dest = c['to'].lower()
            elif c['kind'] == 'webhook' and c['secret'] not in keys:
                dest = destination(c['url'], hosts)
                keys.add(c['secret'])
            else:
                raise ValueError('invalid webhook channel')
            if dest in seen:
                raise ValueError('duplicate destination')
            seen.add(dest)
            self.channels[c['id']] = c
            self.bindings[c['id']] = hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()
        self.state = state
        self.guard = threading.Lock()
        for key, default in [('delivery_queue', []), ('delivery_dead', []), ('delivery_budget', {})]:
            state.data.setdefault(key, default)

    def dead(self, item, t, reason):
        log = self.state.data['delivery_dead']
        log.append({k: item[k] for k in ('id', 'channel', 'attempts')} | {'time': t, 'reason': reason})
        del log[:-256]

    def enqueue(self, event, t, check='watchdog'):
        # Caller saves this together with the transition under the state lock.
        incident = str(uuid.uuid4())
        for channel, c in self.channels.items():
            if event not in c['events']:
                continue
            item = dict(id=str(uuid.uuid4()), channel=channel, attempts=0, due=t, created=t,
                        binding=self.bindings[channel], body=json.dumps(dict(version=1, event=event,
                        incident=incident, time=int(t), summary=f'{event}: {check[:64]}')))
            queue = self.state.data['delivery_queue']
            if len(queue) < 256:
                queue.append(item)
            else:
                self.dead(item, t, 'overflow')

    def run(self):
        while True:
            self.drain()
            time.sleep(5)

    def drain(self, t=None, send=deliver):
        if not self.guard.acquire(blocking=False):
            return
        try:
            timestamp = time.time() if t is None else t
            with self.state.lock:
                queue = self.state.data['delivery_queue']
                dirty = False
                for item in queue[:]:
                    reason = ('configuration' if self.bindings.get(item['channel']) != item['binding'] else
                              'expired' if timestamp-item['created'] >= 86400 else
                              'exhausted' if item['attempts'] >= 3 else None)
                    if reason:
                        self.dead(item, timestamp, reason)
                        queue.remove(item)
                        dirty = True
                if dirty:
                    self.state.save()
                if not queue:
                    return
            # One due item per channel per pass; reserve durably before I/O.
            for channel, c in self.channels.items():
                with self.state.lock:
                    now = time.time() if t is None else t
                    item = next((x for x in queue if x['channel'] == channel and x['due'] <= now), None)
                    slots = self.state.data['delivery_budget'].setdefault(channel, [])
                    slots[:] = [s for s in slots if s > now-3600]
                    if item is None or len(slots) >= 6:
                        continue
                    slots.append(now)
                    item['attempts'] += 1
                    item['due'] = now + 10 * 2**(item['attempts']-1) + random.uniform(0, 4)
                    self.state.save()
                status = send(c, item, int(now))
                transient = status in (0, 408, 429) or 500 <= status < 600
                with self.state.lock:
                    if not transient or item['attempts'] == 3:
                        queue.remove(item)
                        if not 200 <= status < 300:
                            self.dead(item, now, 'exhausted' if transient else 'rejected')
                    self.state.save()
        finally:
            self.guard.release()


if __name__ == '__main__':
    try:
        print(send_one(*json.load(sys.stdin)))
    except (ValueError, ssl.SSLCertVerificationError):
        print(400)
    except (OSError, http.client.HTTPException):
        print(0)
