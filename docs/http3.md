# HTTP/3 in wrest

**Status: disabled by default.** Only HTTP/1.1 and HTTP/2 are negotiated.

## Why

HTTP/3 = QUIC = UDP port 443. TCP 443 is universally allowed; UDP 443 is not
(corporate firewalls, VPNs, captive portals). When UDP is blocked, WinHTTP's
MsQuic stack waits the full QUIC handshake timeout (~10 s) before falling back
to TCP. That penalty is per-connection and makes things feel broken.

Browsers dodge this with **Alt-Svc discovery** (first request over TCP, server
advertises `h3` support, subsequent requests upgrade) and **Happy Eyeballs
racing** (TCP and QUIC in parallel, use whichever wins). WinHTTP does neither —
it tries QUIC sequentially and eats the timeout on failure.

reqwest also treats HTTP/3 as opt-in (compile-time `http3` feature, no Alt-Svc
or racing). We mirror that default.

## WinHTTP primitives

Requires Windows 11 21H1+ / Server 2022+.

| Option | Scope | What |
|---|---|---|
| `WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL` | Session **or request** | Bitmask: `0x0` = H1 only (default), `0x1` = H2, `0x2` = H3 |
| `WINHTTP_OPTION_HTTP_PROTOCOL_USED` | Request (read-only) | Which protocol was actually negotiated |
| `WINHTTP_OPTION_HTTP3_HANDSHAKE_TIMEOUT` | Session or request | QUIC handshake timeout (ms), default ~10 000 |
| `WINHTTP_OPTION_HTTP3_INITIAL_RTT` | Session or request | Initial RTT estimate for MsQuic |
| `WINHTTP_OPTION_HTTP3_KEEPALIVE` | Session or request | QUIC keep-alive interval (ms) |
| `WINHTTP_OPTION_QUIC_STATS` | Request (read-only) | QUIC connection statistics |

The protocol-enable option defaults to `0x0` — both H2 and H3 are explicit
opt-in, there is no auto-negotiation. We set `0x1` (H2) on the session. The key
detail: this option can be set on **individual request handles**, enabling
per-origin H3 opt-in without affecting other requests.

## Future: Alt-Svc discovery

The safe path to HTTP/3 without timeout regressions: never try QUIC unless the
server already told us it supports it.

1. First request goes over H2/TCP as usual.
2. Parse `Alt-Svc: h3=":443"; ma=3600` from response headers.
3. Cache the origin as h3-capable (keyed by `(host, port)`, expires per `ma`).
4. Subsequent requests to that origin: set `ENABLE_HTTP_PROTOCOL = H2 | H3` on
   the **request handle**. WinHTTP tries QUIC.
5. After response, check `HTTP_PROTOCOL_USED`. If H3 wasn't negotiated despite
   being enabled, negative-cache the origin (middlebox blocking UDP).

```rust
struct H3Cache {
    /// Origins that advertised h3. Key: (host, port), Value: expiry.
    origins: RwLock<HashMap<(String, u16), Instant>>,
    /// Origins where QUIC failed despite Alt-Svc. Key: (host, port), Value: retry-after.
    blocked: RwLock<HashMap<(String, u16), Instant>>,
}
```

Lives in `ClientInner` (already `Arc`-shared). Hook points:
- After `WinHttpOpenRequest`: check cache, set per-request H3 flag
- After response headers: parse `Alt-Svc`, update cache
- After `query_version()`: if H3 was enabled but H2 was used, negative-cache

### `http3_prior_knowledge()`

Skips Alt-Svc, sets `WINHTTP_PROTOCOL_FLAG_HTTP3` on the **session** (all
requests). Caller accepts the timeout risk. Useful when you control the server.

## Risks

| Risk | Mitigation |
|---|---|
| Server advertises h3 but middlebox blocks UDP | Negative cache after first failed QUIC attempt |
| Cache memory growth | LRU bound (~1024 entries) + `ma`-based expiry |
| QUIC timeout even with Alt-Svc | Reduce `HTTP3_HANDSHAKE_TIMEOUT` to ~3 s for discovered origins |

## References

- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 7838 — Alt-Svc](https://www.rfc-editor.org/rfc/rfc7838)
- [WinHTTP option flags](https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags)
