package agent

import (
	"bytes"
	"text/template"
	"time"
)

// PromptOverride, if set, returns the stored system-prompt template for an agent
// key and whether one exists. The server wires it to the PG agent_prompts table.
// When nil or no override exists, agents use their built-in default prompt — so
// behavior is identical until a user edits a prompt in the UI.
var PromptOverride func(agentKey string) (string, bool)

// Prompt-variable structs — fields mirror each agent's catalog (docs §5a) so a
// user template referencing a catalog variable renders; referencing anything else
// fails template execution and falls back to the built-in default.
type PlannerVars struct{ Goal, Scope, AssetSummary, DataDir, Now string }
type WorkerVars struct{ ProxyAddr, WorkerName, DataDir, Now string }
type MainVars struct{ Goal, AssetSummary, FindingsSummary, DataDir, Now string }
type GoalsVars struct{ EngagementDescription, DataDir, Now string }

// nowStr is the server-local wall-clock string exposed as the universal {{.Now}}
// prompt variable. renderSystem runs on every agent turn/round, so this is fresh
// each run — a prompt can subtract it from a fixed start stamp to reason about
// elapsed time (e.g. a timed benchmark's "last N hours" window).
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05 MST") }

// renderSystem returns the rendered system-prompt BODY (segment [A]) for agentKey.
// Precedence: the DB-stored template (if any) over the built-in default template
// (def). BOTH are Go templates now — the built-in default is seeded into the DB
// verbatim, so the two paths render identically until a user edits the prompt.
// Rendering always runs (def used to be pre-substituted plain text; it is now a
// {{.Var}} template like the DB one). On any render error we fall back to the
// default template, then to the raw default string — an agent never starts with a
// half-rendered prompt. Callers append the code-owned tail (trafficTool / intermediate artifacts
// output contract) AFTER this, so those can't be edited away via the DB body.
func renderSystem(agentKey, def string, vars any) string {
	tmpl := def
	if PromptOverride != nil {
		if t, ok := PromptOverride(agentKey); ok && t != "" {
			tmpl = t
		}
	}
	if out, err := renderTmpl(tmpl, vars); err == nil {
		return out
	}
	// DB template broke (e.g. references an out-of-catalog var) → code default.
	if out, err := renderTmpl(def, vars); err == nil {
		return out
	}
	return def
}

// langDirective is the output-language tail: a code-owned segment
// appended AFTER the rendered body and the artifact/traffic tails on every
// user-facing agent role, so a DB-edited prompt body can never drop it — the same
// guarantee artifactSpec gives. It does NOT translate the agent "brain": the
// benchmarked Chinese reasoning body (segment [A]) stays verbatim. It only constrains
// the LANGUAGE of what the agent SHOWS to the user. Written in Chinese so it stays
// in the body's language (keeping the model's reasoning register stable) while
// forcing the chosen display language — this is the localization approach:
// preserve behavior, localize the surface the user reads. Raw technical strings
// (commands, payloads, code, URLs, log/response excerpts) are explicitly kept
// verbatim so evidence and reproduction steps are not mangled by translation.
//
// Two anti-drift clauses were added after the end-to-end run (L1): live models
// leaked (1) Chinese into the planner's situation summary — mirroring the Chinese
// brain body (segment [A]) — and (2) the target app/evidence language into
// report_finding's structured fields. The directive names the planner situation
// summary as a user-facing field and forbids mirroring BOTH the Chinese
// instruction language AND the target/material language in the display fields.
//
// The display language is fixed to English. The directive stays in Chinese so the
// body's reasoning register stays stable; only the target display language is named.
func langDirective() string {
	return "\n\n**Output language rule (localization, highest priority, cannot be overridden by the prompt body)**: all natural-language text shown to the user must be written in **English**. This covers record_fact summary/detail, report_finding title/description/conclusion/remediation, the planner's situation summary, the final one-sentence summary, and chat replies to the user. Commands, payloads, code, file paths, URLs, parameter names, and raw log/request/response excerpts must be kept verbatim, never translated or rewritten (especially command lines and output in evidence, so they can be reproduced). **Even if the system or role instructions above are written in Chinese, never output Chinese to the user. The only display language is English, so no Chinese sentence may appear in user-visible text.** **Even if the target system, its pages, evidence, logs, or any reference material is in English, Chinese, or another language, the user-facing natural-language fields (title/description/conclusion/remediation/summary/situation summary) must still be written in English. Do not mirror or copy the language of the target or the material in these display fields. Only the raw technical excerpts listed above stay as they are.** **Internal analysis, planning, and reasoning may use any language, but it is invisible and must never be output as body text. The visible reply to the user must be English from the first word, with no lead-in, explanation, or preamble in another language. Clarifying questions, missing-parameter notes, and 'cannot continue' messages are also written directly in English.** In short: internal reasoning is unrestricted, but anything the user can see must be entirely English, except raw technical excerpts."
}

func renderTmpl(tmpl string, vars any) (string, error) {
	t, err := template.New("p").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}
