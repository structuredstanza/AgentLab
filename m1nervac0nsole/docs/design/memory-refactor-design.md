<!-- Design record (2026-11-12). Shipped. -->

# Memory layer refactor - design v2 (after adversarial review)

Repo: /mnt/Research/AgentLab/m1nervac0nsole. Nothing is implemented. v1 was reviewed by two agents (code feasibility, live-data replay on task 1); what they overturned is listed at the end. Replay SQL and numbers: `local://memory-replay-evidence.json`.

## Diagnosis

Capture works; delivery does not. Task 1: workers wrote 87 reflections and 23 knowledge entries, but only 12 distinct worker reflections were ever rendered into a later worker's prompt. 7 of 54 workers called `recall`.

| Cause | Evidence |
|---|---|
| Renderer stops at the first line that does not fit; bodies go in unclipped | db/knowledge.go:1019-1021,1054-1056. Every nonempty round block held 1 knowledge entry; 44/54 launches carried 1 reflection; 8 launched with reflections available and none rendered |
| A second clip after the provider cuts whatever the renderer produced | agent/tools_memory.go:53-55,325 (1,200 runes) |
| Engine heuristic rows crowd out agent-written ones | 22/44 visible reflection blocks; 13 "defence response" rows matched file sizes, hex blobs and the engine's own hook messages (db/reflect_engine.go:52-54,316-339) |
| Start block is a frozen per-bundle snapshot | 43 workers got the identical 2,142-char block (server/memory.go:143-151) |
| Selection never sees the intent | server/memory.go:89-125,175-219 read task id/name/goal only |
| Negative results are not memory | i28's "only msg consumed" (fact 33) was absent when i89 re-ran the same probing 3 h later |
| Stale advice is never corrected | R31 "RCE route closed" stayed live after i94 got RCE through it; R36 "stop pursuing RCE" ranks #3 for a post-RCE intent |
| Budget-exhausted runs lose their lesson | settle wrap-up prompt never mentions reflect (agent/worker.go:193; second wording agent/wrapup.go:132) |
| Scrubber corrupts technique text | 18 replacements in 9 knowledge writes; 11 are `::` -> `<ip>` (`[Convert]::ToBase64String`), 2 loopback addresses |
| recall is weak | Go tokeniser disagrees with the Postgres parser; `ts_rank_cd` has no IDF and rewards repetition; reflections substring-scored over newest 50 of 300; 500-rune clip with no read-by-id |
| Cross-task needs a human per entry, with no prompt to act | no queue, no notification |
| `rsi_lessons` inject path skips scrub and marker filter | db/lessons.go:257-266 (only when RSI_LESSONS=inject; default off) |

## Principles

1. Delivery over capture. Do not depend on the model calling recall.
2. One selector, one packer. The packer owns the budget; the ledger records what the packer wrote.
3. Measured before clever. Replay showed correct packing alone recovers most of the loss; relevance ranking must beat recency in a judged replay before it replaces it.
4. RSI.md rules stand: machine writes are scrubbed task-private candidates; agents never change status; promotion is the owner's.

## Phase 1 - delivery repair (no schema change)

1. Packer (replaces the write loops in `RenderMemory` / `RenderReflections` and the post-clip in `reflectionsBlock`): skip an item that does not fit instead of stopping; clip each item to ~300 runes; return the ids it wrote. `recordKnowledgeUsage` is called with those ids, so "shown" means shown. No new ledger table.
2. Launch/round block: 4 reflection slots; agent-written rows before engine rows; identical summaries collapsed at render time ("x3").
3. Start block: knowledge only (adopted environment entries + goal-matched hits, bodies clipped). The 4 frozen opsec/noise reflections are removed; the launch/round block carries reflections and is rebuilt every time.
4. Delete the substring defence-response heuristic (reflect_engine.go:316-339). There is no per-intent HTTP status to replace it with: tool results are raw text and the traffic store has no intent link.
5. Settle wrap-up: a code-owned step appended the way `withWrapupLang` appends (agent/wrapup.go:107-112), placed before the final sentence because settlement ends on the first text-only turn: one `reflect` naming what blocked the run and what the next worker should do differently. Applies to both wordings. `reflect` is callable in settlement (only Bash is hidden).
6. recall:
   - tsquery built by Postgres from its own parse (`string_agg(quote_literal(lexeme),' | ')::tsquery` over `unnest(to_tsvector('english',$q))`), `ts_rank_cd(tsv,q,2|32)`, `COALESCE` for the stopword-only NULL query, lexemes present in most candidate rows dropped (no IDF otherwise).
   - reflections searched in SQL over their existing tsv (all rows), replacing the in-Go substring scan.
   - typed ids `K12` / `R93`; `recall(id)` returns one full item under the same visibility predicate as search (db/knowledge.go:527-531; task_id for reflections). Today's `GetKnowledge` / `GetReflection` have no visibility check, so a bare id lookup would leak across tasks.
   - results carry status, age and origin intent.
7. Scrub precision: an IPv6 candidate must parse and contain a hex group and not touch identifier characters or `]`; loopback/unspecified addresses are not identifiers; regression corpus = the 18 observed corruptions plus `basic authentication`, `Set-Cookie:` attributes, slash-separated lists.
8. `RenderLessons` goes through `ScrubSecrets` + `memoryRenderLine`.

Tests that change: `TestTaskMemoryBlock` (start block), `TestRecallScoresReflectionsByTermOverlap`, `TestRecallTruncatesBodiesAndMatchesReflections`, the reflectionsBlock clip test (agent/tools_memory_test.go:490-493), the defence-signal cases in `TestDeriveIntentReflectionsSignals`. Worker guidance is at 899/900 bytes, so new instructions go into tool descriptions (SeedTool propagates them; live rows are not operator-edited).

## Phase 2 - intent-aware selection

One `SelectMemory(MemoryQuery{TaskID, IntentID, Surface, Text, Budget})` in `db/memory_select.go`; `server/memory.go` keeps block assembly only; `memoryHits`, `roundKnowledge`, newest-N `ListReflections` in blocks and recall's scorer are deleted.

- Asset relation is a read-time join, no new columns for reflections: `task_reflections.intent_id -> exploration_anchors.asset_id`. Join on anchors, not payload JSON (`intentAssetIDs` returns nil on any type mismatch; seed and human intents carry no `asset_ids`).
- `knowledge_entries.origin_intent_id` (one additive column, stamped from `RunInfoFrom(ctx).IntentID`; 0 for planner/main agent) gives task knowledge the same join and gives the promotion queue its evidence link.
- Order: items whose origin intent shares an asset with this intent first; inside each group, recency. Lexical rank on the intent text is a third key only after the gate below. In a single-host task (44/54 intents on one asset) the asset key is a no-op and the order degrades to recency, which is today's rule minus the packing bug.
- Prior attempts: a query-time view, not a store. Eligible = finished intents anchored to one of this intent's assets. Each is represented by its best-matching yielded fact (lexical match against this intent's text), falling back to the latest `activity.kind='result'` summary, then its detail. Rendered through `memoryRenderLine`:
  `[I28 done, 2 facts] fact: JSON-field probing consumed only msg`
  Delivered in the worker launch block only (3 slots).
- Verdicts: `reflect` gains optional `about: ["R31"]` + `verdict: confirmed|wrong|stale`, stored in the existing `signal` JSONB of a normal reflection row (already bounded and scrubbed). The selector attaches the newest verdict to its target at render time: `R31 ... (disputed by R75, intent 94: ...)`. Nothing is suppressed and no status changes, so an agent - or target text steering one - cannot silence an opsec row. Available to planner and worker.
- `GET /api/memory/preview` takes `intent_id` so the operator sees the block a given worker would get.

Gate for lexical ranking: on the task-1 replay, hand-judge top-4 for 20 launches under (a) recency and (b) asset+recency+lexical. Ship (b) only if it wins; replay already shows it is not obviously better (i43 got SQL speculation in its top 3; R36 ranked #3 after RCE).

## Phase 3 - cross-task, owner gate unchanged

- An in-app notice instead of a push notification (owner decision during implementation: `notify/` only knows finding events, renders finding cards, and delivers to whatever chat or mailbox receives vulnerability alerts). Finished tasks with candidates show "N to review" on the tasks list and a notice on the task detail page, both linking to the review queue; one `GET /api/knowledge/review/counts` query feeds them.
- A "Review" view on /system/memory: this task's candidates ordered by origin-intent outcome (yielded a confirmed finding > yielded facts > none), with the promotion redaction count and the nearest adopted entry by title/FTS. Bulk promote uses the existing endpoint (knowledge ids only; reflections still graduate one by one first).
- Promotion from a soft-deleted/archived task currently fails (db/scrub.go:164-170) and hard delete cascades candidates away: the queue must be offered before archive, and the archive dialog should say how many unreviewed candidates will be lost.

## Acceptance

Replay on task 1 (launch time = the intent's first activity row; reflections only - knowledge bodies are overwritten on same-title upsert and cannot be replayed):
- distinct worker-written reflections rendered across launches: 12 today -> >= 40.
- i111's launch block contains R83.
- i89's launch block contains i28 with the fact-33 line in its 3 attempt slots.
- every ledger row corresponds to rendered text; no block exceeds its budget.
- scrub corpus round-trips; existing `TestScrub*` pass.
- unchanged and green: task isolation, scope rules, caps, generalisation on write/promote, render flatten/neutralise, curator-only tools.

## Not doing

- Reflection consolidation/merge. Replay: at similarity 0.90 it absorbs 10/87 and the merges are wrong (R83 folded into R78, which gives the opposite advice; a later correction merged into the stale advice it corrects); at 0.95 it merges nothing. It also collides with engine dedupe keys and the "overflow is an error, not a silent drop" rule.
- Facet columns / GIN. `assets.technologies` is free text written by agents and the operator, unscrubbed, and populated on 3 of 15 assets in task 1.
- `memory_exposure` table and utility scoring. Too few exposures per item per task to mean anything; nothing in the evidence needs it.
- `proof_basis` column. `kind` already encodes it (unproven playbook -> lead).
- `similar_prior_attempts` on `add_intent`. Workers claim an intent within 800 ms, so the advice lands after the intent is committed; the planner already has recent_done_intents, cold digests, the stagnation warning and the churn trigger.
- Embeddings/pgvector, LLM consolidation or auto-delete, agent-editable core memory, auto-adoption.
- Mid-run push of a sibling's opsec reflection into a running worker: wanted, depends on whether `steer_work` reaches a worker mid tool call (unverified).

## What review overturned in v1

| v1 claim | Finding |
|---|---|
| Identical start block keeps the prompt prefix cacheable | The worker system prompt already differs per intent (run dir at agent/worker.go:331-333,371); cross-intent cache reuse was given up deliberately (worker.go:469-473) |
| Recurrence (`hits >= 2`) pins R83 | R83 is `noise`, R86 is `mistake`, and R86 did not exist when i111 launched. R83 was newest #2: a pure packing loss |
| Intent-description similarity finds i28 for i89 | Ranks i28 #4-#10; best yielded-fact match with asset overlap as eligibility ranks it #3 |
| Lexical top-3 raises delivery to >= 40 | 37; four slots give 43. Plain newest-three, correctly packed, reaches 54 |
| Facets never carry identifiers and are never model-supplied | `technologies` is agent/operator free text |
| `disputed` status suppresses wrong rows | Agent-set status change violates RSI rule 4 and is steerable by target text |
| No pinned tests change | Five tests change (listed in Phase 1) |

## Amendment - format: index plus on-demand body, not RAG

Measured on the live DB: 17 adopted global entries, 24,620 body chars (avg 1,448), avg title 92 chars; 15 task candidates, avg body 1,336, avg title 101. All six sampled adopted bodies open with a "When <condition> ..." sentence. Reflections: avg summary 172, avg detail 336.

- The row format is already card-shaped (descriptive title, cue-first body, short reflection summary). The defect is rendering whole bodies into a 2,200-char block: one body is 66% of it.
- Phase 1 item 3 becomes: the start block is an index - one line per visible entry, `K17 [technique] <title>` - with full text only for adopted environment entries. 17 lines are about 1,900 chars, so today every adopted entry is visible to every worker with no ranking at all. Bodies come from `recall(id)`.
- The round/launch block lists the task's own candidates the same way (15 lines, about 1,700 chars) next to the 4 reflections.
- When the index outgrows its budget (roughly 20 entries at today's 2,200 chars), rank which titles appear by same-asset origin, then FTS on the intent text, and end with "N more: recall(query)". A ranking miss then costs a title, not the knowledge.
- `reflect` gains `scope: target|tooling` (stored in `signal`). Tooling lessons are shown to every worker regardless of asset; without it the same-asset ordering hides them from workers on other assets.
- Embedding retrieval is deferred until a judged replay shows FTS missing entries through vocabulary mismatch and the adopted set is in the hundreds. External-corpus RAG is not planned: `skills/` is that channel.
- Unverified: whether workers pull a body after seeing its title. Measure `recall(id)` calls per launch on the first task run with the index.

## Outcome (implemented and measured)

Shipped in Phases 1-3 minus the cuts above, plus the in-app notice. Replay against task 1 through the deployed binary (`GET /api/memory/preview?task_id=1&intent_id=...` for all 54 intents, each rendered as of its launch):

| Measure | Before | After |
|---|---|---|
| Distinct agent-written reflections delivered across launches | 12 of 87 | 69 of 87 |
| Launch block | 1 reflection, 1 knowledge body, often identical across workers | median 2,337 chars, none over the 2,400 budget, 2 empty (launched before any memory existed) |
| i111 launch block contains R83 | no | yes |
| i89 launch block shows the prior JSON-probing attempt (i28) | no | yes (3rd attempt slot) |
| Start block | 2 environment bodies + up to 4 goal-matched bodies | index of all 17 adopted entries, 2,124 chars, plus `recall(id=...)` |
| Review queue for task 1 | n/a | 15 candidates, all `unknown` origin (the column is new; older rows default to 0) |

Attempt lines are clipped to 215 runes so all three slots fit the 700-rune section; the first implementation clipped at 300 and silently dropped the third (i28), which the replay caught.
