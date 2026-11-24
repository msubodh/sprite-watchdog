# Threat model: the restart path

**Goal**: an outside watchdog can get a stuck job scheduler restarted, but a compromised watchdog, Fly account or network path cannot do anything worse than that.

| Control | Where |
|---|---|
| No inbound path. The home server only makes outbound HTTPS POSTs; the kick request rides back in the reply. | `watchdog_link.py` |
| No credentials for the home server exist on Fly: no SSH key, no Access token, no shell. | design |
| Hard-coded allowlist of 4 units. Config can only narrow it (set intersection). | `HARD_ALLOWLIST` |
| Only one action exists: `systemctl --user start --no-block <unit>`, run as an argv list with no shell. It runs as the unprivileged user manager, never root. `start` cannot stop or kill anything. | `execute()` |
| Unit names must match `^[a-z0-9][a-z0-9@._-]{0,62}\.(service\|timer)$` and be on the allowlist. | `wdproto.UNIT_RE` |
| HMAC-SHA256 with domain separation (`hb` vs `ord`). The reply signature is bound to the request nonce, so old replies cannot be replayed. | `wdproto.py` |
| Heartbeats: timestamp within ±300 s, nonce single-use. | Sprite handler |
| Orders: 10-minute expiry, single-use ids, at most 4 per reply, at most 1 per unit per 30 min, at most 6 per 24 h. | `vet()` |
| Append-only audit logs on both sides (`events.jsonl`, `link-events.jsonl`). | both |
| The heartbeat carries no secrets, hostnames or IPs. Paths in status lines are replaced with `<path>`. | `collect()` |
| Third-party keys (Resend, Workers AI) live in Sprites connectors with deny-by-default policies limited to this Sprite's name and to the one API path it needs. | connector policy |

**Residual risk**: anyone holding the HMAC key (the Sprite and the home server) can request up to 6 scheduler starts a day. Each one is harmless by construction. Rotating the key means writing a new key to both sides.
