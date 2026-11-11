# Recursive self-improvement in ARTEX

Status: measurement and shadow memory only. There is no harness search, no
automatic adoption, and no self-modifying code in this repository.

This file defines the contract any future harness-optimization work must meet,
so the first experiment cannot quietly become an unguarded rewrite loop.

## The three loops

| loop | object | state |
|---|---|---|
| A. within a task | planner, worker, retester, adversarial gate | exists |
| B. across tasks | evidence-gated lessons from closed tasks | shadow mode, PR #104 |
| C. on the harness | prompts, skills, tool guidance | **not built**; this is its contract |

Loop A produces task gain. Loop B is meant to produce retained gain: a lesson
must survive a closed task and change a later one. Loop C is the only loop that
can produce improver gain, and it is the only one that can silently damage the
product, which is why it goes last.

## Loop C contract

Any PR that proposes, probes, or adopts harness edits must satisfy all of:

1. **Live tasks propose, benchmarks adopt.** A successful bounty task can
   generate a candidate lesson or edit, but it can never be the evidence for
   adoption. Adoption requires held-out benchmark runs, because a live task is
   unreproducible and contaminated by its target.
2. **Owner approval per adoption.** The loop may prepare a proposal branch and
   show the diff. It may not change the active prompt. Adoption is one explicit
   owner action, like a baseline pin.
3. **Immutable surfaces.** The following are never in the search space:
   the adversarial and quality gates, scope and authorization checks,
   prompt-injection defenses, tool allowlists, and the code-owned prompt tails
   (traffic tools, artifact rules, lesson block). Only the editable prompt body,
   skill markdown, and tool descriptions can be proposed.
4. **One-step rollback.** Every adopted prompt change is a new
   `agent_prompts` version, so rollback is a pointer change. Skills are files
   under git; no adoption may bypass review.
5. **Flag off by default.** The loop runs behind a feature flag. Turning it on
   requires an owner decision, and the flag is checked per run.
6. **Bounded edit budget.** A round may propose a bounded number of edits
   (annealed over rounds). A critic proposes only edits that are expected to
   transfer; a pruner rejects edits that only fit the probe task. This follows
   RRSI (arXiv 2609.24972).
7. **Attribution.** Probe results are compared against an unchanged baseline on
   the same task and seed. Regressions are attributed to a specific module
   rather than to the loop as a whole; the modular fault-localization idea is
   from ModularRSI (arXiv 2609.14857). A paired evolving/non-evolving comparison
   guards against misattributed safety regressions, following SEABench
   (arXiv 2609.35596).
8. **No self-approval and no silent state.** The loop cannot set its own status,
   edit its own acceptance criteria, or write to the lesson library as
   `adopted`. Lesson status changes stay owner actions.

A future Loop C PR is acceptable only with:

- a benchmark adapter and a held-out task set, independent of the tasks used to
  propose the edit;
- a baseline run and a candidate run with the same model, seed, budget, and
  judge;
- the judge independent of the subject model, with a falsification battery
  (the existing L3 runner already enforces this);
- per-gate results with denominators, not a single aggregate score;
- a written rollback path and the flag name.

## What the current layers do

- `GET /api/tasks/{id}/outcome` (PR #102) records what a task produced and what
  it cost: findings by disposition and severity, retest verdicts, tokens, tool
  calls, skill misses, wall time.
- `ARTEX_RSI_LESSONS=off|shadow|inject` (PR #104) extracts evidence-gated
  lessons from terminal tasks and, in `inject` mode, appends a code-owned
  data-not-instructions block after the planner and worker system prompts.
  Status stays `candidate`.
- `GET /api/skill-gaps` (PR #106) turns the existing miss ledger into a
  capability backlog.

None of these changes an agent's instructions on its own. Shadow mode exists to
measure whether retrieval helps before any harness edit is attempted.

## Memory: knowledge base and reflection pool (Loop B)

Two stores feed an agent's working memory. Neither edits a prompt body, a gate
or a skill; both stay inside Loop B (data an agent may read), never Loop C.

- **Knowledge base** (`knowledge_entries`). Searchable technique, tool, opsec,
  indicator, playbook, lead and note entries. Retrieval is Postgres full-text
  search over title, tags and body with the `english` configuration, so an
  inflected word still matches: the query is tokenised and the terms are
  ORed, ranked by overlap, because ANDing a natural-language question against
  one entry returns nothing. The operator's own list filter keeps AND and falls
  back to the ORed form, flagged `relaxed`, only when AND finds nothing.
  Scopes are `global`, `environment`, `company` and
  `task`; `environment` holds what is true of the platform the agents run on
  (proxy behaviour, network shape) rather than of a target, carries an
  `env:<name>` tag, and its adopted entries are injected at task start whatever
  the task is about. `lead` is a route that was reasoned out but never executed:
  `knowledge_add` takes a `proof_basis`, and a `playbook` that cannot cite
  `executed-live` or `executed-lab` is stored as a `lead`. Shortcut: keyword
  recall only, no semantic search; upgrade to pgvector when an embedding
  provider is configured.
- **Reflection pool** (`task_reflections`). What one task learned, per
  kind: `opsec` (what a defender could see), `noise` (redundant or low-yield
  work), `lookfor` (leads not chased), `learning`, `mistake`. Two sources: the
  engine derives them from run data at the end of every intent and at task close
  (error rate, duplicate requests, no-yield intents, guard denials, defence
  responses, finding quality, calls per finding, skill misses), and agents add
  their own with `reflect` before finishing an intent.

Loop closure: the planner prompt carries a "Recent reflections" block every
round and each worker intent receives the same block, so the next batch sees
what the last one learned. The block is rebuilt every round, so a lesson written
mid-task is read by the next one. At task start the adopted environment entries
and the knowledge hits for the task name and goal are added to the code-owned
memory block next to the lesson block.
Everything rendered is flattened to one line, length capped and framed as data
from earlier work, because it can contain target-controlled text.

Operational security rules, all enforced in code:

1. Every write is scrubbed for credentials (bearer tokens, key=value secrets,
   JWTs, cloud keys, private keys, URL userinfo, cookies, long opaque blobs).
2. Agent-written entries are task-private candidates, generalised on write with
   the task's own identifiers replaced, so a lesson reads as a condition and a
   mechanism rather than as one box's address (the concrete values stay in the
   exploration graph). A candidate never leaves its task, so nothing crosses an
   engagement until the owner promotes it.
3. Promotion to company or global scope is an owner action and re-scrubs the
   entry with the origin task's scope identifiers (hosts, IPs, company names)
   replaced by `<target>`, `<ip>` and `<email>`. The response reports how many
   redactions were made.
4. An agent can never set `adopted`; status changes stay owner actions, as for
   lessons.
5. Per-task caps (50 agent knowledge entries, 300 reflections) and field length
   caps bound noise. Overflow is an error, not a silent drop.

Flag: `ARTEX_MEMORY=off|inject` (default `inject`), read per task-bundle build.
Deleting a task deletes its task-scoped knowledge and reflections.

Curation (owner side). `/system/memory` browses both stores, edits and promotes
entries, graduates a reflection into a task-scoped candidate, and previews the
exact block a task would be injected with (`GET /api/memory/preview`).
`knowledge_usage` records which entries were read back - start-of-task block,
per-round block, or an agent's `recall` - so a dead entry is distinguishable
from a load-bearing one; it is best-effort telemetry and never fails a prompt
build. The `curator` assistant shares the chat stack and is propose-only: its
five tools (`memory_search`, `memory_read`, `memory_propose`,
`reflection_search`, `task_digest`) are bound to that agent alone, and its
writes are task-scoped candidates, generalised like any other agent write.
Promotion stays the owner's.

## Credits

The admission rule (no lesson without cue, action, and evidence) and the
propose/probe/compose shape come from:

> Harness^2: Recursive Agent Harnessing for an Open World.
> Ruiyao Xu, Yanfei Chen, Zhongying CuiZhu, Bhavana Dalvi Mishra, Yifei Ming,
> Han Yu, Rujun Han, Chen-Yu Lee, Tomas Pfister. arXiv:2610.14224, 2026.
> Google Research. Apache-2.0. https://github.com/google-research/harness2

The evidence taxonomy used in the design (task gain, retained gain, improver
gain) and the implementation pointers come from:

> awesome-rsi, lobehub. https://github.com/lobehub/awesome-rsi

Specific ideas referenced above:

- RRSI: Regularized Recursive Self-Improvement of Agent Harnesses,
  arXiv:2609.24972 (annealed edit budget, critic and pruner).
- ModularRSI: Modular and Generalizable Recursive Harness Self-Improvement,
  arXiv:2609.14857 (module-level fault localization from success/failure
  contrast).
- SEABench: Benchmarking Endogenous Misalignment in Self-Evolving Agents,
  arXiv:2609.35596 (paired evolving/non-evolving attribution).
- Agentic Harness Engineering: Observability-Driven Automatic Evolution of
  Coding-Agent Harnesses, arXiv:2604.25850 (observable edits with predictions
  verified later, the same discipline as the benchmark gate here).
- A Safety in Self-Evolving Agents survey, arXiv:2610.00093 (why properties
  must survive accumulation and cross-context reuse, not just entry screening).

Only ideas are borrowed. ARTEX code is independent Go and Python; no source
from harness2 or the referenced projects is copied.
