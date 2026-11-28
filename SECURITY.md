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
| Legacy delivery uses scoped Sprites connectors. Registered email instead uses a dedicated `MAIL_` environment credential sent only to Resend; webhook keys use the separate `HOOK_` namespace. Keys pass to the bounded delivery child through its environment, never config or persisted state. All registered references must resolve at startup. | connector policy / registered channel transport |

**Residual risk**: anyone holding the HMAC key (the Sprite and the home server) can request up to 6 scheduler starts a day. Each one is harmless by construction. Rotating the key means writing a new key to both sides.
## Registered webhook receivers

Only register HTTPS hosts you control. Each attempt checks all DNS answers, connects directly to a checked IP, and verifies TLS against the registered name. Redirects are terminal. Keep keys distinct from heartbeat credentials. Never embed credentials in a URL.

Verify `X-Watchdog-Signature` with a constant-time comparison to `v1=` followed by the lowercase hex HMAC-SHA256 over `v1\n<Timestamp>\n<Delivery>\n` (UTF-8, LF separators) followed by the original request body bytes. Timestamp and Delivery are the literal `X-Watchdog-Timestamp` and `X-Watchdog-Delivery` headers. Reject ambiguous headers, malformed UUIDs, invalid signatures and timestamps more than five minutes from current Unix time. Atomically record authenticated delivery IDs with processing; retain for at least 25 hours and return 2xx for valid duplicates. Retries keep the body and ID. The sender ignores response bodies. Only authenticated outbound heartbeats can pull restart orders.
