# Tests

One entry point for every suite. Run all of them, or name an area.

```sh
tests/run.sh            # everything
tests/run.sh go         # m1nervac0nsole Go tests
tests/run.sh proxy      # provider-proxy tests
tests/run.sh python     # lab / guest-start / export_traces (stdlib unittest)
tests/run.sh web        # Next.js UI
tests/run.sh dev        # dev-launcher process contract
```

The Go suites need a database for `db` and `server`:

```sh
export M1NERVAC0NSOLE_PG_DSN='postgres://postgres@127.0.0.1:55770/m1nervac0nsole?sslmode=disable'
```

## Why most Go tests are not in this directory

Go requires a test file to sit in the same directory as the package it tests, so a
`_test.go` in `db/` cannot be relocated without rewriting it. There are two kinds:

- **White-box** (`package db`, `package server`, …) — the majority. These call
  unexported functions directly, which is what lets them test the real logic
  rather than a public wrapper. Moving one means either exporting the internals it
  touches, or rewriting it as a black-box test of the exported API. Both make the
  code worse to satisfy a folder layout, so they stay beside their code.
- **Black-box** (`package foo_test`) — these use only the exported API, so they can
  live anywhere. They are in `m1nervac0nsole/tests/go/`.

If you are looking for a test, use the index below; if you are running one,
`tests/run.sh go` covers every package including the co-located ones.

## Index

### `m1nervac0nsole/tests/go/` — relocated black-box Go tests

| Package | Tests | What it covers |
|---|---|---|
| `m1nervac0nsole/tests/go/manifest` | 12 | Tool manifest parsing, emission, golden fixtures, live builtin manifest |
| `m1nervac0nsole/tests/go/scope` | 16 | Engagement scope: exclusion rules, enforcement |
| `m1nervac0nsole/tests/go/useragent` | 1 | Every outbound request sets an identity header (source walk) |

Fixtures for the manifest goldens live in `m1nervac0nsole/tests/go/manifest/testdata/golden`.

### Go tests kept beside their package

| Area | Files | Tests |
|---|---|---|
| `server/` | 112 | 346 |
| `db/` | 56 | 183 |
| `agent/` | 45 | 120 |
| `third_party/norma/` | 34 | 147 |
| `traffic/` | 14 | 49 |
| `notify/` | 11 | 96 |
| `llmrec/` | 6 | 14 |
| `intercept/` | 5 | 20 |
| `guard/` | 5 | 7 |
| `evidence/` | 5 | 9 |
| `llmpool/` | 4 | 22 |
| `sidequestion/` | 3 | 14 |
| `mcphttp/` | 3 | 3 |
| `config/` | 2 | 3 |
| `egress/` | 1 | 6 |
| `limits/` | 1 | 14 |
| `nativeproxy/` | 1 | 11 |
| `cmd/m1nervac0nsole/` | 1 | 2 |

### `tests/python/`

| File | What it covers |
|---|---|
| `test_lab.py` | VM lifecycle, export, provider proxy wiring |
| `test_guest_start.py` | Guest supervisor: process start, tunnel gate, capture |
| `test_export_traces.py` | Trace export, spill, provenance |

### `deployment/cliproxy/`

The provider proxy is a patched build of a pinned upstream, so its tests clone the
tag, apply `core.patch`, and run against that. `run-tests.sh` does this in a
temporary directory and cleans up. Tests of the host-side additions live in
`internal/infer`, `internal/server`, and `internal/privacy`.

### `m1nervac0nsole/web/`

Vitest, run with `tests/run.sh web`.
