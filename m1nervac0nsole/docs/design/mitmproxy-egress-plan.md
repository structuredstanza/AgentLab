<!-- Design record (2026-11-13). Shipped. -->

# Recording proxy x egress proxy: diagnosis and plan

Status: diagnosed, not fixed. Reproduced in the lab guest on 2026-11-13.

## Symptom

Through the recording proxy (`-x 127.0.0.1:8788`):

| Request | Result |
|---|---|
| `http://example.com/` | **502 Bad Gateway**, empty body, no `X-M1nervac0nsole-Egress` header |
| `https://example.com/` | 000 without `-k`, **200 with `-k`** |
| `http://172.16.0.6:8099/` (in-scope fixture) | 502 |

Direct (`--noproxy '*'`) and through the masking egress proxy (`-x 127.0.0.1:8888`, absolute-URI form) both return 200. Task 2's directory contains no traffic index at all, so nothing was captured.

## Root cause

Two facts, each verified in code and by experiment.

1. **go-mitmproxy always CONNECTs to its upstream, even for `http://` targets.** `proxy.getUpstreamConn` (go-mitmproxy v1.9.2, `proxy/proxy.go:122-135`) calls `helper.GetProxyConn`, which unconditionally writes `CONNECT <host:port>` (`internal/helper/proxy.go:65-70`). There is no absolute-URI path for a plain HTTP target.
2. **The egress proxy terminates every CONNECT tunnel as TLS.** `egress/proxy.go:261-263` routes CONNECT to `p.mitm`, which builds `tls.Server(...)` (`:294`) and speaks TLS. Its only plaintext path is `forwardPlain` (`:345`), which handles non-CONNECT absolute-URI requests and is why `curl -x 8888 http://...` works.

So a plaintext HTTP request through the recorder is sent into a tunnel the egress proxy has already turned into a TLS session: the bytes are consumed by a TLS handshake that never completes, and the recorder answers its client with a bare 502.

Proof by experiment (guest):
```
curl --proxytunnel -x http://127.0.0.1:8888 http://example.com/
  > CONNECT example.com:80
  < HTTP/1.1 200 Connection Established
  > GET / HTTP/1.1
  status=000        # no response: the tunnel is not relaying plaintext
```

HTTPS is not broken: the recorder MITMs the client, then speaks TLS to the egress proxy, which terminates it and re-originates with the uTLS fingerprint. The recorder does not verify the upstream certificate (`SslInsecure: true`, `traffic/traffic.go:206`, used at `proxy/attacker.go:232`), so the egress CA is accepted. The 000 without `-k` is the *client* rejecting the recorder's own CA, which agent tools avoid by trusting `M1NERVAC0NSOLE_EGRESS_CA`; it is expected, not a bug.

## Why it matters

- Every `http://` target is uncaptured. Internal services, lab boxes and the browser fixture are routinely plain HTTP, so "the traffic becomes evidence" fails exactly where evidence matters most.
- The failure is silent to the agent: it sees a 502, concludes the target is down, and works around it with `--noproxy '*'` - which removes the traffic from the capture entirely (observed in task 2).
- The recorder's own failures are unattributed: a bare 502 with no header cannot be told apart from a target's answer, which is the same class of bug the egress proxy already fixed with `X-M1nervac0nsole-Egress`.

## Options

**A. The egress proxy relays non-TLS CONNECT tunnels verbatim (recommended).**
RFC 9110 says a CONNECT tunnel is opaque bytes; terminating TLS on a port-80 tunnel is the defect. In `mitm`, peek one byte after the CONNECT reply: `0x16` (TLS handshake) keeps today's path; anything else is relayed raw to the target with `io.Copy` both ways, after the existing liveness probe.
- Cost: S-M (one function, a small relay, tests).
- Gain: plain HTTP is captured; TLS keeps the fingerprint.
- Loss: the plaintext path cannot be header-masked (nothing to rewrite without parsing), so the UA mask does not apply to `http://`. The source IP still exits through the egress proxy, so no host leaks the real address.
- Risk: a mis-detected first byte breaks TLS tunnels. Mitigate with a one-byte peek and a short deadline, defaulting to today's behaviour on any doubt; add a test that a TLS ClientHello still reaches `tls.Server`.

**B. The recorder dials `http://` targets directly (fallback).**
In `traffic.Open`'s upstream function, return nil when `req.URL.Scheme == "http"`. One line plus a test.
- Gain: capture works immediately.
- Loss: plain HTTP leaves from the guest's own IP, unmasked - unacceptable for a real engagement, fine for a lab.
- Use as an opt-in (`M1NERVAC0NSOLE_RECORDER_HTTP_DIRECT=1`) if A is rejected, or as a stopgap.

**C. Patch go-mitmproxy to use absolute-URI HTTP for upstream `http://` targets.**
Correct in principle, but it means a vendored fork of the proxy for one code path, and the upstream project would have to accept it. Not recommended while A is available.

**D. Point the recorder at a plain CONNECT relay instead of the masking proxy.**
A second hop that only tunnels would restore capture but loses the mask for everything, not just plain HTTP. Worse than A.

## Recommended course

1. **Attribute the failure first (S).** Give the recorder's own error responses a header (`X-M1nervac0nsole-Recorder: dial-failed|upstream-failed`) the way the egress proxy does. Without it, the next operator debugs this from scratch. One addon hook, one test.
2. **Implement option A (S-M).** Peek, branch, relay; keep the liveness probe before answering CONNECT so "the port is open" stays a fact.
3. **Keep option B behind an env flag (S)** as the escape hatch for a lab where masking plain HTTP does not matter.
4. **Document the client-side trust requirement** in the proxy skill/README: a client that does not trust the recorder CA sees 000 on HTTPS, which is not a proxy failure.

## Verification

Unit (egress):
- CONNECT to a plaintext server relays the request and the response byte-for-byte.
- CONNECT carrying a TLS ClientHello still reaches `tls.Server` and the fingerprint test still passes.
- A dead target still answers 502 with the attribution header before any tunnel exists.

Integration (guest, after deploy):
```
curl -x 127.0.0.1:8788 http://example.com/            # 200, and a traffic row appears
curl -k -x 127.0.0.1:8788 https://example.com/        # 200, and a traffic row appears
curl -x 127.0.0.1:8788 http://<fixture>:8099/login    # 200, captured
```
Then re-run the browser verification gate (`local://open-items-plan.md` section 1) with the strict fixture: its first request must no longer 502, and the run must produce traffic rows.

## Rollout

Fix on a branch, run the full CI jobs locally, push, deploy with `./lab build && ./lab stop && ./lab start --vpn ...`, then run the integration commands above in the guest before touching the browser gate. If A regresses TLS, revert to B behind the flag and re-plan.

## Open questions

- Does the egress proxy's rate limit (100 rpm per target) apply to the relayed plaintext path? It should, or a capture-heavy task can flood a target.
- Should the plaintext relay also apply the header mask by parsing the request line? That would restore masking at the cost of a second HTTP parser in the proxy; decide only if a real engagement needs masked plain HTTP.
