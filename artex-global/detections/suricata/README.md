# ARTEX detection rules (Suricata / network)



The network-layer companion to the [Sigma rules](../sigma/). These [Suricata](https://suricata.io)
signatures cover the one ARTEX artifact that is observable on the wire, and every indicator is grounded in a
string verified in this repository's source, not inferred. The host, log, and SIEM layers live
under [`../sigma/`](../sigma/); the [English defense guide](../../docs/defense-en.md) explains the full picture.

## Rules — [`artex.rules`](artex.rules)

- **sid 1000003** — `ARTEX worker WebFetch User-Agent`. An inbound HTTP request whose User-Agent starts with
  `norma/` — the norma SDK's WebFetch tool (`github.com/Autumn-27/norma/tool/webfetch.go`). This UA is hardcoded across all norma
  versions (v0.1.0–v0.4.3, verified) and reaches the target through the recording proxy, which does not
  modify request headers (`traffic/traffic.go`). It fires during the **attack phase** (active vulnerability
  probing). `classtype: attempted-recon`.

Sids 1000001 and 1000002 (the enrichment prober's presence and high-rate rules) are retired: the prober no
longer sends a distinctive User-Agent, so those signatures could never match again.

## Scope and honesty — read before deploying

- **One ARTEX User-Agent is network-observable.** The norma SDK's WebFetch tool sends `norma/0.4`
  (`github.com/Autumn-27/norma/tool/webfetch.go`) during the attack phase. The recording proxy
  (`traffic/traffic.go`) does not modify request headers, so that UA reaches the target on the wire. The
  asset-enrichment prober has **no** static fingerprint: it presents the engagement's masked browser
  identity, so at the target it is indistinguishable from ordinary browser traffic and there is no
  User-Agent rule for it — detect enrichment by behaviour (rate, breadth, sequence) instead. Other worker
  tools (Bash subprocesses like `curl`, `nmap`) use their own User-Agents — detect those with generic
  scanner signatures and the behavioural SIEM rules under [`../sigma/`](../sigma/).
- **The User-Agent is only visible in plaintext.** It appears where traffic is plaintext HTTP or inspected at
  a TLS-terminating proxy / WAF. End-to-end TLS encrypts it, so deploy these where you actually see the HTTP
  request buffer.
- **A static User-Agent can be changed** by the operator, so its absence does **not** mean safety. The durable
  signal is behaviour — rate, breadth, and sequence — which is why the Sigma correlation layer keys on it,
  and why pure web multi-stage detection needs base rules specific to your environment.
- **Deliberately omitted.** The self-update User-Agent `artex-selfupdate` travels over HTTPS to GitHub and is
  not network-observable (TLS SNI alone is too common to alert on). The audit-control marker is an
  operator-side log artifact, not target-facing traffic — detect it with
  [`../sigma/artex_guard_audit_framing.yml`](../sigma/artex_guard_audit_framing.yml). The server port `:8787`
  and recording proxy `127.0.0.1:8788` (`cmd/artex/main.go`) are host-forensic (`ss`/`netstat`), not a
  network signature.
- **The norma User-Agent is shared, not ARTEX-specific.** Sid 1000003 matches `norma/`, emitted by
  the owned SDK at [`../../third_party/norma/tool/webfetch.go`](../../third_party/norma/tool/webfetch.go)
  (based on BaaRai/Norma v0.4.4). Other norma-based applications emit the same prefix.
  The [indicators list](../indicators/README.md) therefore keeps it out of atomic blocking indicators.

## Validate and test

Validated with Suricata 8. The load test needs no traffic and always runs:

```sh
# syntax + engine load test (expect: "Configuration provided was successfully loaded")
docker run --rm -v "$PWD/detections/suricata":/r -w /r jasonish/suricata:latest \
  suricata -T -S artex.rules -l /tmp --init-errors-fatal
```

`--init-errors-fatal` makes a rule that parses but fails to initialise a hard error too, so the load test
cannot pass with a silently dropped signature.

To confirm the rules actually fire, a reproducible regression test lives in
[`../tests/suricata/`](../tests/suricata/). It runs this same load check first, then synthesizes a
deterministic capture with scapy, runs `suricata -r` over it, and asserts the alert counts — needing only
Docker:

```sh
detections/tests/suricata/run.sh
```

It asserts that sid 1000003 fires exactly once per WebFetch request (8 over an 8-flow capture) and that
the same capture with a benign browser User-Agent produces **0** alerts — confirming the signature is
specific. See [`../tests/README.md`](../tests/README.md). To check against your own traffic instead, capture
a loopback `curl -A 'norma/0.4'` against a local server and read the alerts:

```sh
suricata -r norma.pcap -S artex.rules -l out && \
  grep -c '"signature_id":1000003' out/eve.json    # presence: one per request
```

## Contributing

Detection contributions are welcome. New rules should keep every indicator grounded in an observable fact,
state limitations in a comment, pass `suricata -T` cleanly, and avoid any content that reads as attack
guidance. See [`../../CONTRIBUTING.en.md`](../../CONTRIBUTING.en.md) and the Sigma layer in
[`../sigma/`](../sigma/) / [`../README.md`](../README.md).
