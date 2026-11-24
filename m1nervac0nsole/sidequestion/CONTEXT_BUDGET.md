# Long Side-Question Conversations and Context Budget

English

Revised 2026-09-11. The previous implementation treated the character count of the request JSON as the token count and inherited the main task's 32K output reservation unchanged, so it prematurely rejected valid side questions when there was a lot of HTML, JS, or tool output.

## Comparison with Open-Source Implementations

- [Grok CLI side-question context](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/agent/agent.ts#L739): Extracts selected portions of the most recent user and assistant text, with a character budget of about 2000 characters and a maximum of 400 characters per item. This path does not maintain a continuous side-question conversation history.
- [Grok CLI standalone request](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/utils/side-question.ts): Uses a separate cancellation signal. The output limit is 2048 tokens if supported by the model. No tools are provided.
- [Grok CLI main-session compaction](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/agent/compaction.ts): Estimates tokens, retains recent content, incorporates new content into the previous summary, and handles truncation across turn boundaries.
- [OpenCode session compaction](https://github.com/anomalyco/opencode/blob/b3f1a96c6dd7adeb28b36dd11add1998fc84d67b/packages/core/src/session/compaction.ts): Estimates the entire request, reserves output and buffer, combines recent content with a rolling summary, and sends a summary request without tools. By default, this implementation uses a recent-content budget of 8000 and a summary output limit of 4096 tokens.
- [OpenCode overflow recovery](https://github.com/anomalyco/opencode/blob/b3f1a96c6dd7adeb28b36dd11add1998fc84d67b/packages/core/src/session/runner/llm.ts): Attempts overflow recovery only if assistant output has not yet started, and the recovered call does not re-enter the same overflow-recovery path.

The console adopted the approach of a separate output budget, recent content plus a rolling summary, and limited recovery. It retains norma v0.3.6's structured messages and tool pairing, but does not directly adopt Grok's text-extraction approach, nor does it record OpenCode's main-session compaction events in the m1nervac0nsole main transcript.

## Request Budget and Execution

- Messages use norma's approach: estimate UTF-8 bytes by content block and add a 4/3 margin. System prompts, tool schemas, and message-wrapping overhead are also counted. This estimate is not the model's exact token count.
- Side-question output is limited to 8192 tokens by default and does not exceed an output limit already set in the main configuration. The service environment variable `M1NERVAC0NSOLE_BTW_MAX_OUTPUT_TOKENS` can set a limit in the range 256–32768; it does not change the product's default model or the main task parameters.
- The input budget is the context window minus the output limit and a safety margin; if the window size is unknown, the platform default of 200K is used. The safety margin is 5% of the window, with a minimum of 128 tokens and a maximum of 8192 tokens.
- Successful exchanges are loaded in increasing ordinal order, up to 20 groups at a time. Up to 20 groups of original text are retained; their token budget is no more than 1/4 of the input budget and never exceeds 16K.
- Exchanges that exceed the budget are incorporated into a rolling summary. The summary includes source records and the context point in time. Past assistant answers are not equivalent to new tool evidence, so the latest main snapshot takes precedence in case of conflict.
- If the main context is still too long, only older messages in a copy are summarized, retaining up to 8K tokens of recent content. Truncation does not split tool calls from their results. If a single group is too large, the entire group is included in the summary.
- Summary input is safely divided by UTF-8 size to fit the actual remaining window, and the output limit is 2048 tokens. Empty summaries, truncated responses, tool calls, and summaries exceeding the budget are never written to the cache. A single side question makes at most 12 summary calls, all subject to the same 120-second timeout. On reaching the limit, it fails clearly instead of looping indefinitely.
- If the model returns a context overflow for the first time before emitting any text or tool calls, the request is reduced further and retried at most once. Recovery stops immediately if the estimated size does not decrease. Other model errors or partially streamed output do not trigger this recovery.
- All usage already aggregated, including usage from summaries, failed attempts, and cancellation points, is accumulated for the same side-question request. If the provider does not return usage, only 0 is recorded; estimates are not presented as actual usage.

## Persistence and UI

`side_question_sessions.memory` stores summaries of older exchanges, the incorporated ordinal, and main-context summaries cached by snapshot identity. `side_question_requests.context_info` stores preparation state, the number of groups actually reloaded, summary usage, and budget estimates.

Summaries are saved only while the original request is still running and the cleanup version matches. Clearing also deletes the cache, and late writes do not resurrect data that has already been cleared. A new snapshot does not reuse a summary from a previous snapshot. Summary fields are stored with v3 task archives; when restoring an older v3 without those fields, they are filled with empty objects, while v1 and v2 remain compatible.

POST accepts and returns the request first; preparation and compaction run in the background without holding the admission lock or a database transaction. SSE and the history UI display preparation, exchange compaction, copy compaction, and response stages. Compaction failure is stored as a failed terminal state for that side-question request. The frontend retains the error and restores the draft of the question that failed this time, while floating notifications do not obscure the input. History polling also no longer clears submission errors.

## Verification Record

- Replays of 19, 20, 21, and 50 groups; preservation of older conclusions beyond 20 groups; and reuse of the summary cache after restart: automation passed.
- Very long answers with multibyte text and code context, request budget splitting, tool pairing, snapshot immutability, and cache invalidation for new snapshots: automation passed.
- Summary failure, cancellation, truncation, overlength, tool return, clear-operation races, call limit, a single overflow recovery, and no retry after partial streaming: automation passed.
- Pagination, restart, v1/v2/v3 archives, archive restoration of summary cache and budget metadata, older v3 without new fields, and 20 parent sessions sharing four concurrent execution slots in a standalone PostgreSQL instance: passed.
- Go candidate service build, frontend TypeScript check, Biome check of the modified component, and Next.js production build in a separate directory: passed.
- Using the embedded browser with an isolated UI fixture at 1280×720 and 390×844 resolutions, verified the exchange-compaction stage, summary-scope notice, draft restoration after failure, absence of floating error notifications, absence of horizontal overflow, and absence of console errors. The temporary fixture was removed.
- Replaying an already-local Worker snapshot read-only passed the new budget check. For example, the 293085-character snapshot for Worker #3 is no longer incorrectly rejected by the local character-count calculation. This item made no external model calls.
- The real conversation test that attempted to send a private Worker snapshot to Grok was rejected by automatic approval review and therefore was not run; it is not counted as a pass.
- At the user's request, the local backend was restarted at 2026-09-11 00:37 using the original database, data directory, and login settings. The SHA-256 hashes of the executable and candidate binary matched, and `/api/health` returned healthy from both the backend and frontend proxy.

Verification commands (using only a standalone test DB):

```sh
go test -race ./sidequestion ./db ./server -run 'TestSide|TestCheckpoint|TestSnapshot|TestBuildRequest|TestService|TestMainSide|TestTaskArchive' -count=1
go build ./cmd/m1nervac0nsole
npx tsc --noEmit
npm run build -- --webpack
```

The frontend production build used a separate copy so as not to overwrite the current preview's `.next`. The candidate service is at `/private/tmp/m1nervac0nsole-btw-budget-candidate` and was copied to `/private/tmp/m1nervac0nsole-btw-preview/m1nervac0nsole` to run. The original binary was backed up as `m1nervac0nsole.before-context-budget` in the same directory.