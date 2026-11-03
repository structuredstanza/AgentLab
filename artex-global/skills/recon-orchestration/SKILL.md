---
name: recon-orchestration
description: "Invoke this skill when a hunt task needs to decide which reconnaissance tools to run, in what order, with what parameters, against a target whose technology stack is only partly known — and when the honest answer to 'run everything' is a ranked, budgeted plan instead of a scan dump. Covers target profiling, tool ranking by target type, parameter derivation, failure classification, and when to stop."
---

# Reconnaissance Orchestration

Under an **authorized** engagement only. The problem this skill solves is not "which tool exists" — it is "given this target, this time budget and this program's rules, which three tools are worth running and what do I pass them."

Running every tool produces a scan dump nobody triages and a lot of off-scope noise. Running none produces no findings. The value is in the ranking and the stop condition.

## Phase 1: profile the target before choosing tools

Classify what you are looking at, because tool choice depends entirely on it:

| Target type | Signal | Consequence |
|---|---|---|
| **Web application** | URL, HTML, cookies, a login | Content discovery, template and parameter testing |
| **API endpoint** | `/api/` path, JSON responses, OpenAPI doc | Parameter discovery, authz testing, no crawling |
| **Network host** | bare IP, non-HTTP ports | Service versioning first, then per-service |
| **Binary or package** | file, APK, archive | Not this skill — `exploit-dev`, `rea` |
| **Cloud resource** | `*.amazonaws.com`, bucket hostnames | Configuration exposure, not web scanning |

Record the evidence for the classification. "It looks like a web app" is not a profile; "port 443, `X-Powered-By: Express`, `/api/v1/health` returns JSON" is.

Then detect the stack — from headers, response bodies, error pages, cookie names, and path conventions. The stack determines which *specific* tests are worth the budget: a WordPress target makes `wpscan` the highest-value single tool; a GraphQL endpoint makes schema introspection the first step; a static site makes content discovery nearly worthless.

## Phase 2: rank tools, do not list them

For the classified target, rank candidates by expected value per unit of budget, not by familiarity:

| Target | Highest value first | Why |
|---|---|---|
| Web app, unknown stack | `nuclei` (curated templates), `katana` (crawl), `ffuf` (content) | Templates carry the expertise; crawling finds the surface; content discovery finds the unlinked |
| Web app, known CMS | CMS-specific scanner first | Generic templates mostly miss CMS-specific issues |
| API endpoint | Parameter discovery, then authz testing | The bugs live in object references and missing parameters, not in paths |
| Network host | Service versioning, then per-service enumeration | Version determines everything downstream |
| Anything with a login | Auth flow analysis before fuzzing | Session handling and authz are where the findings are |

**Budget the run.** State the wall-clock and request budget before starting, and stop at it. A program that forbids scanners changes the ranking entirely — passive sources first, and say so.

## Prefer the manifest tools

Every tool named in the ranking table has a manifest, and `list_tools` reports
which are installed. Call `run_tool` with the manifest id and target rather than
building a Bash command line: the manifest pins the flags, parses the output into
assets and facts, and refuses a target the engagement's boundary excludes. Reach
for Bash only when no manifest covers what you need.

| Category | Manifests |
|---|---|
| Recon | `subfinder`, `dnsx`, `dig`, `whois`, `amass`, `gau`, `wafw00f` |
| Web | `httpx`, `katana`, `ffuf`, `feroxbuster`, `gobuster`, `dalfox`, `whatweb`, `wpscan`, `sqlmap`, `gowitness` |
| Scanning | `nmap`, `masscan`, `naabu`, `rustscan`, `nuclei` |
| Network | `enum4linux`, `enum4linux-ng`, `netexec`, `nbtscan`, `mtr`, `traceroute`, `sslscan`, `testssl` |
| Credentials | `hydra` |
| Intel | `searchsploit` |

## Phase 3: parameters are derived, not defaulted

For each chosen tool, derive parameters from the profile:

- **Rate** from the program's stated limit, not the tool's default. A default `ffuf` run against a production target is a self-inflicted DoS.
- **Wordlist** from the observed stack and naming convention. `common.txt` against a REST API finds nothing; the API's own error messages name its resources.
- **Scope** pinned to the authorized hosts. Never let a crawler follow a redirect off-scope.
- **Exclusions** for the paths the program names as out of bounds (usually auth, payment, admin).

## Phase 4: classify failures instead of retrying blindly

When a tool fails, the failure class decides the response:

| Failure | Response |
|---|---|
| **Rate limited** (429, "too many requests") | Reduce concurrency, wait, resume — not a finding and not a tool problem |
| **Blocked** (WAF page, 403 with a challenge) | This is a **result**, not an error: record it, note the block, and try the bypass set before concluding anything |
| **Timeout** | Reduce scope or wordlist; do not simply increase the timeout |
| **Tool not found** | Say so and substitute; never silently drop the step |
| **Auth lost** (401 mid-run) | Session expired; re-authenticate before continuing, or every subsequent result is invalid |
| **Target unreachable** | Stop. Scanning something that is down produces nothing and may indicate you are off-scope |

A blocked request is the single most misread outcome in recon: it usually means the target defends that path, which is information worth more than a 404.

## Phase 5: stop condition

Stop when any of these is true, and say which:

1. The budget is spent.
2. The planned tools all ran and their output is triaged.
3. You have a candidate that passes the finding gates — go verify it rather than widening the scan.
4. The target is blocking every active path — record the block pattern and stop; more requests only increase exposure.

Never continue scanning because results are thin. A thin result is a result.

## What this skill does not do

It does not exploit, does not verify findings (`codeaudit`, `api-security`, `exploit-dev`), and does not report. Its output is a ranked plan, a bounded execution, and a triaged result set handed to the verification skills.
