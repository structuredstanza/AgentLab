# Contributing

English

Thank you for your interest in m1nervac0nsole (`m1nervac0nsole`). This document
gathers the scope, policies, and procedures you should know before you start contributing.
Before you send a contribution, please read [Authorized use and legal responsibility](#authorized-use-and-legal-responsibility) first.

- To report a bug or suggest a feature → use the [issue templates](https://github.com/structuredstanza/AgentLab/issues/new/choose).
- If you find a security vulnerability → **do not open a public issue**; follow the procedure in [SECURITY.en.md](SECURITY.en.md).
- Everyone who takes part must follow the [Code of Conduct (CODE_OF_CONDUCT.en.md)](CODE_OF_CONDUCT.en.md).

---

## Authorized use and legal responsibility

m1nervac0nsole is an offensive-security tool in which an LLM multi-agent system performs penetration
testing **autonomously**. Contributors are bound by the same scope limits as users.

- When you verify code, run the tool only against **a target you own or have explicit written
  authorization for**, or against a **locally isolated environment** (for example an
  intentionally vulnerable target you own, such as OWASP Juice Shop or DVWA launched with Docker).
- We do not accept code that scans, probes, or exploits real, production, or remote systems
  outside the authorized scope, nor changes that encourage such use.
- In the Republic of Korea, intruding into another party's information and communications
  network without authorization, or causing a disruption to it, violates the Act on Promotion
  of Information and Communications Network Utilization and Information Protection; and any
  personal data collected or exposed falls under the Personal Information Protection Act. The
  full notice is in the [README](README.md#️-read-first--authorized-use-and-legal-notice).

Legal responsibility for how the code or documentation you contribute is used rests with the
user who runs it. This repository is provided "AS IS."

---

## Development environment

This project consists of a **Go backend** (with the frontend embedded in a single binary) plus
a **Next.js frontend**.

The design intent of the main features is documented in the design docs under `docs/`. When you
work on the feature that links vulnerabilities to traffic evidence (the report agent's automatic
binding, `report_finding`'s `traffic_refs`, and so on), read the
[vulnerability multi-traffic-evidence design doc](docs/finding-traffic-evidence-en.md) first.

### Required versions

- Go 1.26 or later (per `go.mod`)
- Node.js 22 or later (per the release workflow)
- Docker and Docker Compose (for local runs and verification)

### Backend (Go)

If Go is installed locally, run the following from the repository root.

```bash
go build ./...
go vet ./agent/
go test ./agent/
```

If you do not have Go locally, you can verify the same way with Docker. Keeping the module and
build caches in named volumes makes re-runs faster.

```bash
docker run --rm -v "$PWD":/src -w /src \
  -v m1nervac0nsole-gomod:/go/pkg/mod -v m1nervac0nsole-gocache:/root/.cache/go-build \
  golang:1.26 sh -c 'go build ./... && go vet ./agent/ && go test ./agent/'
```

#### DB integration tests (postgres required)

The `go test ./agent/` above **quietly skips the DB integration tests** that only run when
connected to PostgreSQL. Nine packages — `agent`, `config`, `db`, `enrich`, `evidence`, `guard`,
`intercept`, `llmrec`, `server` (the `go-db` matrix in
[`../.github/workflows/ci.yml`](../.github/workflows/ci.yml)) — contain tests that require a real
database; if there is no `M1NERVAC0NSOLE_PG_DSN` environment variable and no `database` entry in
the config file, those tests are skipped with `--- SKIP` and the package still ends in `ok`. As a
result, if you fix one of these nine packages and verify without a DSN, **it can pass locally
(ok) while the PR's `go-db` job fails.**

To run these tests locally, bring up PostgreSQL and pass `M1NERVAC0NSOLE_PG_DSN`. The example below
launches the same `postgres:16-alpine` as CI on an isolated network, reusing the named volumes
from above.

```bash
# 1) Bring up an isolated network and an empty postgres (same image and account as CI).
docker network create m1nervac0nsole-db 2>/dev/null || true
docker run -d --name m1nervac0nsole-pg --network m1nervac0nsole-db \
  -e POSTGRES_USER=m1nervac0nsole -e POSTGRES_PASSWORD=m1nervac0nsole -e POSTGRES_DB=m1nervac0nsole \
  postgres:16-alpine
until docker exec m1nervac0nsole-pg pg_isready -U m1nervac0nsole -d m1nervac0nsole >/dev/null 2>&1; do sleep 1; done

# 2) Pass the DSN to run the DB integration packages (the DSN host is the container name).
#    To run only the package you fixed, replace ./agent/ with that package.
docker run --rm --network m1nervac0nsole-db -v "$PWD":/src -w /src \
  -v m1nervac0nsole-gomod:/go/pkg/mod -v m1nervac0nsole-gocache:/root/.cache/go-build \
  -e M1NERVAC0NSOLE_PG_DSN='postgres://m1nervac0nsole:m1nervac0nsole@m1nervac0nsole-pg:5432/m1nervac0nsole?sslmode=disable' \
  golang:1.26 sh -c 'go test ./agent/ -count=1'

# 3) Clean up.
docker rm -f m1nervac0nsole-pg && docker network rm m1nervac0nsole-db
```

CI's `go-db` job **isolates each of these nine packages with its own postgres** and forces them
to run before merge ([`../.github/workflows/ci.yml`](../.github/workflows/ci.yml)). If you changed a DB integration package, we
recommend verifying that package directly with the method above before you open the PR.

### Frontend (web)

For web changes, Vitest, the static export (including TypeScript checks), and Biome
are required merge gates. CI also checks the exported HTML for CJK text.

```bash
cd web
npm ci
npm run dev          # dev server
npm run build        # production build
npm run test -- --run # unit tests (merge gate; vitest)
npm run build:static # static-export build (merge gate; includes TypeScript type checking)
npm run check        # Biome lint/format/a11y check (merge gate; must report zero errors)
npm run check:fix    # auto-fix
```

If you do not have Node 22 locally, or the installed native dependencies do not
match your platform, run the three npm gates with Docker. Keeping `node_modules` in a named
volume avoids clashing with your host's platform binaries (for example `@parcel/watcher` and
Biome) and makes re-runs faster.

```bash
docker run --rm -v "$PWD":/src -w /src/web \
  -v m1nervac0nsole-web-nm:/src/web/node_modules \
  node:22 bash -c 'npm ci && npm run test -- --run && npm run build:static && npm run check'
```

Formatting and linting before commit are managed with Biome. `lint-staged` automatically runs
`biome check --write` on staged files.

### Full run (Docker Compose)

```bash
cp .env.example .env     # set POSTGRES_PASSWORD
docker compose up -d     # start m1nervac0nsole + postgres → http://localhost:8787
```

---

## Contribution process

1. **Open an issue first.** For large changes it is better to align on direction via an issue
   before you start. For small fixes (typos, links, obvious bugs) you can send a PR directly.
2. **Fork** the repository and create a topic branch. Prefix the branch name with the nature of
   the change, as in `feat/...`, `fix/...`, `docs/...`, `i18n/...`.
3. Write the change and **run the relevant verification yourself.** For a Go change, make the
   `build`/`vet`/`test` above pass. For a web change, all three
   [web CI](../.github/workflows/web.yml) merge gates must pass: `npm run test -- --run`
   (Vitest), `npm run build:static` (including TypeScript checks), and `npm run check`
   (Biome, with zero errors). If you changed documentation (`.md`), run
   `python3 -I scripts/check-doc-links.py` to confirm that
   in-repo link/image references and document anchor (`#heading`) links are not broken. Anchors
   are built from headings into slugs with the same rule as GitHub and matched, so if you change a
   heading's text without also fixing the anchor links that pointed to it, it is caught here (CI's
   `docs` workflow enforces the same check as a merge gate). This check is also wired as the
   `docs` hook in the module root's [`.pre-commit-config.yaml`](.pre-commit-config.yaml), so if
   you run `pre-commit install` it runs automatically on every commit (it uses only the Python
   standard library and no network, so it finishes without Docker).
4. **Open a PR.** Follow the [PR template](../.github/PULL_REQUEST_TEMPLATE.md) for the title and
   description, and write what you changed, why, and how you verified it. If you changed the UI,
   attach screenshots.
5. For a user-facing change (feature, localization, documentation, detection rule, and so on),
   add one line to the `[Unreleased]` section of the [changelog (CHANGELOG.en.md)](CHANGELOG.en.md).
   Internal refactoring or test-only changes may be omitted.

### Commit messages

Follow the convention of the existing commit history. The format is `type(scope): description`,
and the description is written in English.

- `type`: `feat` · `fix` · `docs` · `chore` · `refactor` · `test` · `i18n`, and so on
- `scope`: the changed area (`agent` · `web` · `server`, and so on); optional

Examples.

```
feat(agent): record refusal as its own status
docs: add English contributor guide
i18n(web): add dashboard navigation labels to message files
```

---

## License

This project is distributed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. By
submitting a contribution, you are taken to **agree that your contribution is also released under
AGPL-3.0**. In particular, if you modify this project and provide it to users over a network (for
example, as an online service), you must disclose the complete corresponding source code to those
users. The full terms are in the [LICENSE](LICENSE) file.
