# Remainder of the Executioner pull: the four open items

Companion to `executioner-implementation-plan.md` and `browser-hardening-plan.md`.
These are the last items the two source documents (`executioner-pull-plan.md`,
`executioner-implementation-plan.md`) name and the tree does not have. The
findings upsert rule (Plan E2) is deliberately out of scope: the owner decided
the prompt-level duplicate discipline is enough.

Paths are under `m1nervac0nsole/`. Nothing here is implemented.

## Status

| # | Item | Source | Effort |
|---|---|---|---|
| S1 | Draft scope rules from a pasted policy | Plan D step 7 | M |
| S2 | `report_finding` accepts screenshot paths | Plan C, "screenshots ... report_finding accepts the path" | M |
| S3 | Cache the scrub regexps | handoff M10 | S |
| S4 | Accent an edge whose source intent is done | Plan A step 4 | S |
| S5 | Answer the recall question | handoff, "unverified" | verification only |

Order: S3, S4, S2, S1, then S5 as a run.

---

## S1 - Draft scope rules from a pasted policy

Today: `plan/plan.go` already carries a `Scope` section, `db/plan_drafts.go`
already applies scope rows in the apply transaction, and the `drafter` agent has
`plan_context`, `list_tools` and `propose_plan`. What is missing is an entry
point that takes a policy document instead of a conversation about goals.

Change
1. `propose_scope` tool in `server/plan_tools.go`, bound to `drafter` alone:
   - Args: `task_id?`, `summary`, `rules: [{effect, kind, value, note?}]`.
   - Builds `plan.Proposal{Summary: summary, Scope: rules}` and runs the same
     validator and store as `propose_plan`, so there is one validation path and
     one draft table.
   - Returns the draft id and `needs_include_approval`, like `propose_plan`.
   - A validation failure returns every problem at once.
2. Add it to `drafterToolKeys` and the seed, and to the drafter prompt: read the
   pasted policy, emit one rule per line, exclusions for what the policy puts out
   of scope, inclusions only for assets the policy names as in scope, never
   invent a host.
3. Web: the Plan tab gets a second entry ("Draft scope rules") that opens the same
   chat with a starter message. The proposal preview already renders scope rows;
   verify it renders a scope-only draft.
4. Apply is unchanged: a scope-only draft applies through the existing
   transaction, and an inclusion still needs `allow_include`.

Tests: a scope-only proposal validates and stores; an invalid effect or kind is
refused with every error at once; apply creates exactly the listed rows; a
scope-only draft with an inclusion is refused without `allow_include`; the tool
is not callable by worker, planner or auto (the binding test already covers the
pattern).

Acceptance: paste a program policy into the drafter, get a draft with N rules,
apply it, and `GET /api/tasks/{id}/scope` shows exactly those rows.

Risk: a policy that names a host the task does not own would create an inclusion
the operator did not intend. Mitigation: inclusions already need `allow_include`,
and the preview lists every rule before apply.

---

## S2 - `report_finding` accepts screenshot paths

Today: `browser_screenshot` writes a PNG under `tasks/<id>/screenshots/` and
returns its path, and `report_finding` has no field to carry it. The model can
paste the path into `evidence` as text, which is not evidence the UI can render.

Change
1. Schema: `ALTER TABLE findings ADD COLUMN IF NOT EXISTS screenshots JSONB NOT
   NULL DEFAULT '[]'`.
2. `db.Finding` gains `Screenshots []string`; insert, select and the detail
   query carry it.
3. `report_finding` gains `screenshot_paths: []string` (optional). Each path is
   validated before the row is written: relative, no `..`, must start with
   `tasks/<taskID>/screenshots/`, must exist, must be a regular file, and at most
   10 MB; at most 10 paths.
4. The finding detail endpoint returns them; the detail page renders a link (and
   a thumbnail when the image is under 1 MB).
5. The generated report names them under `## Evidence`.

Tests: a valid path is stored and returned; `..`, an absolute path, a missing
file, a directory, a path under another task and an oversized file are each
refused with a message naming the path; eleven paths are refused.

Acceptance: `browser_screenshot`, then `report_finding` with that path, then the
finding detail shows the image.

Risk: a screenshot is a durable artefact under the task directory, which is
deleted with the task. That matches how evidence blobs already behave; the
alternative (copy into `evidence/`) is a second storage path for no gain.

---

## S3 - Cache the scrub regexps

Today: `db/scrub.go:282` compiles `(?i)\b<id>\b` inside the loop over
identifiers, so every field of every candidate recompiles every identifier.

Change: a package-level `sync.Map` from identifier to `*regexp.Regexp`, bounded
at 4096 entries (clear the map when it is exceeded rather than evict one key; the
working set is one task's identifiers). Same pattern shape, same output.

Tests: the existing scrub tests must pass unchanged; a benchmark shows the cached
path avoids the compile; the map does not grow past the bound.

Acceptance: `go test -bench BenchmarkScrubTargetIdentifiers` before and after,
with identical output.

Risk: an unbounded cache keyed by attacker-influenced text would be a memory
growth vector; the bound is the mitigation.

---

## S4 - Accent an edge whose source intent is done

Today: `exploration-graph.tsx:668` animates edges whose target is live. The plan
asked for an edge accent when the source intent is done.

Change: keep the live animation, and give an edge whose source is `done` a
stronger stroke (full opacity and a slightly heavier width) so a finished chain
reads as finished. A live target still wins the animation.

Tests: vitest on the edge builder: done source, live target, neither.

Acceptance: on a task with finished intents, their outgoing edges read as done.

---

## S5 - Answer the recall question

No code. The handoff left one behaviour unverified: whether a worker that sees a
title in its memory block pulls the body with `recall(id)`. The usage ledger now
records `recall`, so one task run answers it: count `recall` calls with an id
against the number of memory lines shown, and record the answer in `RSI.md`.

Acceptance: a number, or a statement that the ledger shows none.

---

## Out of scope

Plan E2 (findings upsert rule) is not built: the owner decided the prompt-level
duplicate discipline is enough, and a store-level upsert would need a rule for
preserving a human-set status that nothing has asked for.
