# fly-watchdog

An outside-in watchdog agent that lives on a [Fly.io Sprite](https://sprites.dev). Built for Fly.io Hacksgiving (23-29 Nov 2026).

**Demo video (75 s):** https://github.com/msubodh/sprite-watchdog/releases/download/hacksgiving-2026/demo.mp4

It watches a Linux server (my dev box) and a handful of public web apps from somewhere that is neither of them. When something breaks, it emails the owner through a Sprites connector, so the Sprite never holds the email API key. When a job scheduler on the home server looks stuck, it can ask the server to restart it. The server only does that after checking the request against its own short allowlist.

## How it works

```
             (outbound HTTPS only, every 5 min, HMAC-signed)
 home server ───────────── heartbeat ─────────────►  Fly Sprite: fly-watchdog
 watchdog_link.py  ◄──── signed reply: kick requests ───  watchdog.py
   │  re-checks every request:                           │ probes public /healthz endpoints on each wake
   │  hard allowlist, expiry, replay, rate limits         │ sleeps between pushes (heartbeat-wake mode)
   ▼                                                      │ email ─► Sprites gateway ─► Resend (connector holds the key)
 systemctl --user start <allowlisted unit>                │ optional 2-sentence summary ─► Workers AI (custom-API connector)
```

- **Sprite side (`sprite/watchdog.py`)**: a single Python process run as a Sprite service. Each cycle it probes the configured endpoints, reads the latest verified heartbeat, applies fixed rules (two failures in a row = DOWN; recovery = RECOVERED; heartbeat silent too long = DOWN (only while the Sprite is awake); a job with no progress for 90 min or blocked by its guard = alert), and sends at most 6 alert emails an hour.
- **Home-server side (`devbox/watchdog_link.py`)**: a user systemd timer (every 5 min). It pushes a small, sanitized snapshot (unit states, local HTTP checks, open job names and ages; no hostnames, IPs or secrets) and acts on kick requests.
- **The kick path is pull-only**. Nothing on the home server listens for the watchdog. Fly gets no SSH key, no shell and no root. The only action that exists is `systemctl --user start --no-block <unit>` for one of four hard-coded units. `start` never stops or kills a running process, and it does nothing when the unit is already active.
- **Connectors**: alert email goes through the Sprites **Resend** connector (`/v1/gateway/resend/<id>/emails`). The optional LLM summary uses a **custom-API** connector pointed at Cloudflare Workers AI. The model only writes prose and never chooses actions.
- **Cost (heartbeat-wake mode, the default)**: the Sprite is not held awake. Every push from the home server, once every 5 minutes, wakes it. It runs one check cycle and goes back to sleep about 30 seconds later, so it is awake roughly 10-15% of the time. Measured always-on cost was about $0.0075 an hour, which puts wake mode at roughly $1 a month. There are no Machines, volumes, Postgres or paid connectors. Trade-off: while the home server is completely dead, nothing wakes the Sprite, so a dead server has to be caught by a separate heartbeat service, such as Healthchecks.io. An always-awake mode (`"keepalive": true`) exists, but it costs about $5.50 a month.

## Run the demo locally (fake targets only)

```bash
head -c 48 /dev/urandom | base64 > /tmp/key && chmod 600 /tmp/key
WD_CONFIG=config/demo.json WD_KEY_FILE=/tmp/key WD_STATE_DIR=/tmp/wd python3 sprite/watchdog.py &   # :8080
WD_KEY_FILE=/tmp/key python3 demo/fake_fleet.py &                                                   # :9000 fake services + fake home server
open http://localhost:8080/            # live status page (demo mode only)
curl -X POST localhost:9000/break/shop # -> DOWN after two cycles, then RECOVERED after /fix/shop
curl -X POST localhost:9000/stall      # -> watchdog requests a scheduler kick; the fake server verifies and acks it
```

## Deploy

Clone to the path the systemd unit expects: `git clone https://github.com/msubodh/sprite-watchdog ~/src/fly-watchdog`.

1. `deploy/deploy-sprite.sh <sprite> <config.json> <hmac.key>` from a clean, committed tree.
2. On the home server, copy `config/link.example.json` to `~/.config/fly-watchdog/link.json` (mode 600). Install `devbox/systemd/*` into `~/.config/systemd/user/` and enable the timer. The unit expects the repo at `~/src/fly-watchdog`; edit `ExecStart` if yours lives elsewhere.
3. Make the Sprite URL public (`url_settings.auth=public`). Every non-health endpoint needs an HMAC signature, and `/status` is off outside demo mode.

## Tests

`python3 -m unittest discover -s tests -v` covers the protocol, signatures, replay protection, the allowlist and rate limits, the rules, and a real HTTP round trip.

See `SECURITY.md` for the threat model.
## Registered notifications

Add these top-level settings to select external deliveries. Omit `alert_channels` for legacy delivery; `[]` disables registered and legacy external notifications. Demo mode does not send. For email only, remove the webhook entry; for both, subscribe both entries to the same events.

```json
{
  "webhook_hosts": ["hooks.example.com"],
  "alert_channels": [
    {"id":"ops","kind":"webhook","events":["DOWN","RECOVERED","STALL","KICK"],"url":"https://hooks.example.com/events","secret":"HOOK_KEY"},
    {"id":"mail","kind":"email","events":["DOWN","RECOVERED"],"to":"you@example.com","sender":"alerts@example.com","secret":"MAIL_KEY"}
  ]
}
```

Provide each named secret in the service environment: an independent random signing key for each webhook, and a Resend API key with a verified sender for email. Deliveries share a 256-item persistent queue. Each channel has six attempts per rolling hour including retries; over-budget items wait. After three transient failures or 24 hours, inspect `delivery_dead` in the local state file (latest 256 records retained up to seven days). Terminal failures dead-letter immediately. KICK is informational; responses cannot request restarts.
