# `/btw` Validation Record

English

Date: 2026-09-10. Branch: `codex/btw-side-question`. Baseline commit: `8dae851b9b622f2ff2631f332fde9719d0b16fba`.

An isolated PostgreSQL test database and data directory were used. Real model credentials were injected only into the isolated test environment and were not written to the code or this record; the product's default model was also left unchanged. Go 1.26.3, norma v0.3.6, Next.js 16.2.9.

The raw model conversations and returned objects from this run were not retained. The assertions below and the summary of what each conversation returned are the record.

## Engineering Checks

All items below passed; the supporting tests are in parentheses.

- Deep copying of structured messages and tool arguments: passed (supported by `TestCheckpointDeepCopyAndBoundaries`).
- Summary and compaction requests do not overwrite; complete responses and terminal status are published; partial responses during generation are excluded: passed (supported by `TestCheckpointDeepCopyAndBoundaries`, `TestSnapshotExcludesPartialStreamAndSelectsPoolMember`).
- Identity of actual model pool member: passed (supported by `TestSnapshotExcludesPartialStreamAndSelectsPoolMember`).
- Tool pairing, 20-batch replay, budget reduction, and over-budget error: passed (supported by `TestBuildRequestCompactionToolPairingAndBudget`).
- Parallel execution of main and side questions, with cancellation isolated in both directions: passed (supported by blocking Provider, `TestMainSideConcurrencyAndIndependentCancellation`).
- No tool execution, streaming and non-streaming, and existing usage on failure: passed (supported by `TestServiceNoToolsAndUsageOnFailure`).
- Actual norma ChatAgent and local Read tool, with main transcript and activity isolation: passed (streaming and non-streaming subcases of `TestSideActualChatCheckpointToolResultAndTranscriptIsolation`).
- Persistence, pagination, idempotency, and partial-response preservation after restart: passed (supported by `TestSideHistoryIdempotencyPagingAndRecovery`).
- Races between clearing and late writes, parent resource deletion, and version comparison: passed (supported by `TestSideClearLateWritersAndDeletedParent`).
- MainAgent and Worker archive and restore (v1, v2, v3): passed (supported by `TestSideTaskArchiveVersions`).
- Three parent interfaces, authentication, resource ownership, and Worker soft deletion: passed (supported by `TestSideHTTPGlobalLimitTaskWorkerAndDeletion`, `TestSideCheckpointPersistsBeforeAdmissionAndRestart`).
- Side questions while the main session is busy, independent SSE reconnect and disconnect, cancellation, and clearing: passed (supported by `TestSideHTTPBusyIsolationClearAndReconnect`).
- One concurrent execution per parent session and four globally: passed (supported by two `TestSideHTTP…` cases).
- Snapshot saved before submission, follow-up after restart, and stale session unable to forge a snapshot: passed (supported by `TestSideCheckpointPersistsBeforeAdmissionAndRestart`).
- Reject continuation if cached configuration is deleted or the model changes: passed (supported by `TestSideRejectsDeletedOrChangedCachedProfile`).
- Cancel before archiving and wait for final response and usage to be saved: passed (supported by `TestSideTaskDrainPersistsBeforeArchive`).
- Record usage only once and attribute it to the side question even if the streaming consumer cancels early: passed (supported by `TestSideUsageRecordedOnceOnConsumerCancellation`).
- Worker runtime and deadline execution context automatically restored after restart continue publishing new snapshots: passed (supported by `TestSideRestoredWorkerRuntimePublishesNewCheckpoint`).
- Race checks for related packages: passed (supported by the command below).
- TypeScript and production build: passed (supported by `npx tsc --noEmit`, `npm run build`).
- Biome checks for newly added frontend modules: passed (supported by `biome check`, 3 new modules).

Automated checks can be reproduced by setting `M1NERVAC0NSOLE_PG_DSN` to a separate disposable database (do not point it at a production database):

```sh
go test -race ./agent ./db ./server ./sidequestion ./llmrec ./llmpool \
  -run 'Test(Side|Checkpoint|Snapshot|BuildRequest|Service|MainSide|CaptureRun|TaskArchive|CompleteForwards|StopIntent|CancelIntent)' -count=1
cd web
npx tsc --noEmit
npx biome check src/lib/side-questions.ts src/hooks/use-side-questions.ts src/components/side-question-workspace.tsx
npm run build
```

The full Go regression tests are not all green. Two existing tests in the `server` package fail during temporary-directory cleanup; both report `TempDir RemoveAll … directory not empty`:

- `TestInheritedActivityDetailAndRelationDeletion`
- `TestTaskMetadataPatchReturnsRenameAndPin`

Running the `server` package again in the same isolated environment using source fetched from the unmodified baseline commit above reproduces the same two cleanup failures. In the baseline commit run, a separate target-node-count assertion failure also appeared in `TestCoreTaskLifecyclePG`, but that assertion failure did not occur in the `server` regression run on the final changes. Other packages passed, as did the side-question-related cases and race checks. The baseline issues were not marked as passing in this validation, and existing assertions were not changed to hide any issues.

The Next.js build emits existing warnings about inference across multiple lockfiles and workspace roots, but the build completes and all pages are generated successfully.

## Browser Checks

Connected to an isolated local Go service and Next.js development server using the Codex built-in browser. Performed the following manual and automated interactions on desktop and a narrow 390 × 844 screen, and checked screenshots and browser logs:

- While regular chat is running, entering `/btw` displays the main content and side question simultaneously; the desktop sidebar also works normally.
- Asked a follow-up question. Stopping the side question preserves the portion already generated, while the main flow continues.
- Closing the panel does not stop the request; reopening it recovers the completed response. After refreshing the page, entering only `/btw` with no content recovers the history.
- In the narrow-screen Drawer, input, buttons, history, and close controls work, with no horizontal overflow.
- Clearing shows a confirmation dialog. After clearing, history is gone, while the main transcript and snapshot remain unchanged.
- Asking and switching between the task's MainAgent and two Workers does not mix agent tabs or histories.
- Using a blocking local model fixture to keep a Worker running, submitted `/btw` through the Worker's main input. Even after stopping the side question, the Worker still showed its live execution state and its own pause button, and the side question saved the partial response.
- Browser error and warning logs are empty.

The controllable fixture was used to precisely verify concurrent execution timing without depending on actual model output speed. During debugging, two Worker execution checks did not produce a valid concurrent interval (the task had already finished or the response had already completed); the fixture was fixed and the checks were rerun successfully. These initial interactions are not counted as valid passes.

## Actual Model Conversations

First, `grok-4.6` was probed. The OpenAI-compatible interface is `http://127.0.0.1:12580/tingly/openai`. The probe returned HTTP 200 with model name `grok-4.6` and `READY`, and took 2.82 seconds. Since the first choice was available, the Tingly `glm` or Zhipu `glm-5.3` fallback chain was not enabled; these two fallback services were not validated this time.

- Asked about assets, goals, and marker while the main session was running: returned `redhaze.top`, the first-page read and goal summary, and `BTW-REAL-0910`; the side question completed (16.97 seconds).
- Asked for tool evidence after the main session read the first page: cited WebFetch 200, curl's 301 → 302 → 200 redirect, and the page title accurately (7.24 seconds).
- Asked the side question to create a test file with Bash: execution was refused and the target file was not created (7.74 seconds).
- Confirmed a completed side question does not change the main context: the main transcript's SHA-256 and main activity record matched exactly; side-question tool execution count was 0.
- Asked a follow-up after actually stopping and restarting the Go service: preserved the previous 3 side-question history entries, answered the asset, marker, and title directly from the persisted snapshot, and did not rerun the main agent.
- Used the Grok non-streaming configuration in a new session: correctly answered the asset and `ATOMIC-0910`, and returned and saved usage (input 11734, output 138, cache_read 11520).

The main session in the asset case read the public first page using WebFetch and Bash/curl; the landing page was `https://id.redhaze.top/home`, and the title returned by the page was "RedHaze Group · Global Conglomerate Portal". Bash briefly saved the response to a local test file only; it did not perform a remote write. This was verified separately from the fact that "the side question did not execute tools."

Main transcript verification value: `e7e61f135a4a120954b539f357e8c4205d7d5cd7460dcaf3dc0fd066463e1d00`.

**Usage limitation:** Tingly's Grok streaming response did not return usage. When `stream_options.include_usage=true` was sent directly for verification, the result was HTTP 200, 12 data frames, and 0 usage frames. Therefore, the 0 in the streaming test means the endpoint does not provide usage; it must not be interpreted as meaning there was no charge. Non-streaming usage and fixture failure/cancellation usage were all saved correctly.

## Qwen Review

The review model was `qwen-flash`, with OpenAI-compatible interface `https://dashscope.aliyuncs.com/compatible-mode/v1`, HTTP 200. The first three actual side-question conversations, tool evidence from the main session, and engineering assertions were provided; it returned `verdict: accept` and `concerns: []`. It judged that the response matched the asset, marker, and page-read evidence, and that the side question's tool refusal complied with the constraints. Review usage: prompt 6625, completion 312, total 6937.

This Qwen review did not include the service-restart and non-streaming tests added later. Qwen's generalization of "no writes" is too broad. The main session's curl did create a local temporary response file, as clearly documented above. Concurrency, zero tool executions, and transcript isolation are established by engineering assertions; model review supplements the response-quality assessment only.