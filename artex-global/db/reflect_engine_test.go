package db

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// seedIntentActivity writes n tool_use/tool_result pairs onto an intent, the
// same shape agent/capture.go emits (worker emit stamps node_id = intent).
func seedIntentActivity(t *testing.T, es *ExplorationStore, intentID int64, uses, results []Activity) {
	t.Helper()
	for _, a := range uses {
		a.NodeID = &intentID
		a.Kind = "tool_use"
		if _, err := es.AppendActivity(a); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range results {
		a.NodeID = &intentID
		a.Kind = "tool_result"
		if _, err := es.AppendActivity(a); err != nil {
			t.Fatal(err)
		}
	}
}

func reflectionByKey(t *testing.T, d *DB, taskID int64, key string) *Reflection {
	t.Helper()
	rows, err := d.ListReflections(context.Background(), taskID, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		if rows[i].DedupeKey == key {
			return &rows[i]
		}
	}
	return nil
}

// TestDeriveIntentReflectionsSignals seeds one intent per signal and checks the
// derived reflection carries the raw counts. A second derive adds nothing.
func TestDeriveIntentReflectionsSignals(t *testing.T) {
	d := memoryTestDB(t)
	ctx := context.Background()
	tk := memoryTask(t, d)
	es := d.Exploration(tk.ExplorationID)

	// Intent 1: 6 calls, 4 errors -> error rate 0.67 with a top failing tool.
	errIntent, err := es.AddIntent(map[string]any{"summary": "error rate"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	var uses, results []Activity
	for i := range 6 {
		uses = append(uses, Activity{Tool: "Bash", ToolUseID: "u" + strconv.Itoa(i), Summary: "Bash step " + strconv.Itoa(i)})
		results = append(results, Activity{Tool: "Bash", ToolUseID: "u" + strconv.Itoa(i), IsError: i < 4,
			Summary: "failed step " + strconv.Itoa(i)})
	}
	seedIntentActivity(t, es, errIntent, uses, results)

	// Intent 2: the same request three times -> duplicate-request noise.
	dupIntent, err := es.AddIntent(map[string]any{"summary": "duplicates"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	seedIntentActivity(t, es, dupIntent,
		[]Activity{
			{Tool: "Bash", Summary: "Bash curl -s https://x/api"},
			{Tool: "Bash", Summary: "Bash curl   -s   https://x/api"},
			{Tool: "Bash", Summary: "Bash curl -s https://x/api"},
		},
		[]Activity{{Tool: "Bash", Summary: "200 OK"}, {Tool: "Bash", Summary: "200 OK"}, {Tool: "Bash", Summary: "200 OK"}})

	// Intent 3: 8 calls, no fact and no finding -> no-yield noise.
	noYieldIntent, err := es.AddIntent(map[string]any{"summary": "no yield"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	uses, results = nil, nil
	for i := range 8 {
		uses = append(uses, Activity{Tool: "Read", Summary: "Read file " + strconv.Itoa(i)})
		results = append(results, Activity{Tool: "Read", Summary: "content " + strconv.Itoa(i)})
	}
	seedIntentActivity(t, es, noYieldIntent, uses, results)

	// Intent 4: platform denials in the tool results -> opsec.
	denyIntent, err := es.AddIntent(map[string]any{"summary": "denials"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	seedIntentActivity(t, es, denyIntent,
		[]Activity{{Tool: "Bash", Summary: "Bash rm -rf /srv"}, {Tool: "Write", Summary: "Write /etc/passwd"}},
		[]Activity{
			{Tool: "Bash", IsError: true, Summary: "[ARTEX platform control - not target defense]This call was blocked by the platform. Reason: destructive command. This operation is forbidden."},
			{Tool: "Write", IsError: true, Summary: "This tool cannot be executed under intercept rule [no-writes]"},
		})

	// Intent 5: three results mentioning a defence -> heuristic opsec.
	defenceIntent, err := es.AddIntent(map[string]any{"summary": "defences"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	seedIntentActivity(t, es, defenceIntent,
		[]Activity{{Tool: "Bash", Summary: "Bash curl"}, {Tool: "Bash", Summary: "Bash curl"}, {Tool: "Bash", Summary: "Bash curl"}},
		[]Activity{
			{Tool: "Bash", Summary: "HTTP 429 too many requests"},
			{Tool: "Bash", Summary: "HTTP 403 forbidden"},
			{Tool: "Bash", Summary: "captcha challenge returned"},
		})

	for _, id := range []int64{errIntent, dupIntent, noYieldIntent, denyIntent, defenceIntent} {
		if n, err := d.DeriveIntentReflections(ctx, tk.ID, id); err != nil || n == 0 {
			t.Fatalf("intent %d: created=%d err=%v", id, n, err)
		}
	}

	r := reflectionByKey(t, d, tk.ID, "intent:"+strconv.FormatInt(errIntent, 10)+":tool-error-rate")
	if r == nil {
		t.Fatal("error-rate reflection missing")
	}
	var sig map[string]any
	if err := json.Unmarshal(r.Signal, &sig); err != nil {
		t.Fatal(err)
	}
	if sig["errors"].(float64) != 4 || sig["tool_calls"].(float64) != 6 || sig["top_failing_tool"] != "Bash" {
		t.Fatalf("unexpected signal: %v", sig)
	}

	if r := reflectionByKey(t, d, tk.ID, "intent:"+strconv.FormatInt(dupIntent, 10)+":duplicate-requests"); r == nil {
		t.Fatal("duplicate-request reflection missing")
	} else if !strings.Contains(r.Summary, "3 times") {
		t.Fatalf("repeat count missing: %q", r.Summary)
	}

	if r := reflectionByKey(t, d, tk.ID, "intent:"+strconv.FormatInt(noYieldIntent, 10)+":no-yield"); r == nil {
		t.Fatal("no-yield reflection missing")
	} else if !strings.Contains(r.Summary, "8 tool calls") {
		t.Fatalf("call count missing: %q", r.Summary)
	}

	deny := reflectionByKey(t, d, tk.ID, "intent:"+strconv.FormatInt(denyIntent, 10)+":guard-denials")
	if deny == nil {
		t.Fatal("guard-denial reflection missing")
	}
	if deny.Kind != "opsec" || !strings.Contains(deny.Summary, "2 tool calls") {
		t.Fatalf("denial reflection wrong: %+v", deny)
	}
	if !strings.Contains(deny.Detail, "destructive command") || !strings.Contains(deny.Detail, "no-writes") {
		t.Fatalf("denial reasons not flattened: %q", deny.Detail)
	}

	if r := reflectionByKey(t, d, tk.ID, "intent:"+strconv.FormatInt(defenceIntent, 10)+":defence-responses"); r == nil {
		t.Fatal("defence heuristic reflection missing")
	} else if !strings.Contains(r.Detail, "Heuristic") {
		t.Fatalf("heuristic not declared: %q", r.Detail)
	}

	// Idempotent: a second derive adds nothing.
	for _, id := range []int64{errIntent, dupIntent, noYieldIntent, denyIntent, defenceIntent} {
		if n, err := d.DeriveIntentReflections(ctx, tk.ID, id); err != nil || n != 0 {
			t.Fatalf("second derive for intent %d created %d (err=%v)", id, n, err)
		}
	}
}

// TestDeriveIntentReflectionsQuietIntent checks a clean intent produces nothing:
// a derive that always writes would be noise, not signal.
func TestDeriveIntentReflectionsQuietIntent(t *testing.T) {
	d := memoryTestDB(t)
	ctx := context.Background()
	tk := memoryTask(t, d)
	es := d.Exploration(tk.ExplorationID)
	intentID, err := es.AddIntent(map[string]any{"summary": "clean"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	seedIntentActivity(t, es, intentID,
		[]Activity{{Tool: "Read", Summary: "Read file"}},
		[]Activity{{Tool: "Read", Summary: "content"}})
	fact, err := es.AddNode(KindFact, map[string]any{"summary": "found something"}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(intentID, RelYields, fact); err != nil {
		t.Fatal(err)
	}
	n, err := d.DeriveIntentReflections(ctx, tk.ID, intentID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("clean intent produced %d reflections", n)
	}

	// An intent of another task is refused, not silently read.
	other := memoryTask(t, d)
	if _, err := d.DeriveIntentReflections(ctx, other.ID, intentID); !errors.Is(err, ErrMemoryInvalid) {
		t.Fatalf("foreign intent should be refused, got %v", err)
	}
}

// TestDeriveTaskReflectionsSignals covers the task-level signals and their
// idempotence.
func TestDeriveTaskReflectionsSignals(t *testing.T) {
	d := memoryTestDB(t)
	ctx := context.Background()
	tk := memoryTask(t, d)
	// tool_usage and skill_usage carry no FK, so deleting the task leaves the
	// ledger rows behind and pollutes the global aggregates other tests read.
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM tool_usage WHERE task_id=$1`, tk.ID)
		_, _ = d.Exec(`DELETE FROM skill_usage WHERE task_id=$1`, tk.ID)
	})
	for _, status := range []string{"false_positive", "duplicate", "confirmed"} {
		id, err := d.AddFinding(tk.ID, 0, "xss", "xss "+status, "high", "summary", "evidence", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.SetFindingStatus(id, status); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 6 {
		if err := d.InsertToolUsage(&ToolUsage{ToolKey: "Bash", AgentKey: "worker", TaskID: tk.ID, IntentID: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.InsertSkillUsage(&SkillUsage{Skill: "missing-skill", AgentKey: "worker", TaskID: tk.ID, Found: false}); err != nil {
		t.Fatal(err)
	}

	if n, err := d.DeriveTaskReflections(ctx, tk.ID); err != nil || n != 3 {
		t.Fatalf("created=%d err=%v", n, err)
	}
	quality := reflectionByKey(t, d, tk.ID, "task:finding-quality")
	if quality == nil || quality.Kind != "noise" {
		t.Fatalf("finding-quality reflection missing: %+v", quality)
	}
	if !strings.Contains(quality.Summary, "2 of 3 findings were rejected") {
		t.Fatalf("unexpected summary: %q", quality.Summary)
	}
	learning := reflectionByKey(t, d, tk.ID, "task:calls-per-finding")
	if learning == nil || learning.Kind != "learning" {
		t.Fatalf("calls-per-finding reflection missing: %+v", learning)
	}
	if !strings.Contains(learning.Summary, "6 tool calls produced 1 confirmed findings") {
		t.Fatalf("unexpected summary: %q", learning.Summary)
	}
	lookfor := reflectionByKey(t, d, tk.ID, "task:skill-misses")
	if lookfor == nil || lookfor.Kind != "lookfor" || !strings.Contains(lookfor.Summary, "missing-skill") {
		t.Fatalf("skill-miss reflection wrong: %+v", lookfor)
	}

	if n, err := d.DeriveTaskReflections(ctx, tk.ID); err != nil || n != 0 {
		t.Fatalf("second derive created %d (err=%v)", n, err)
	}
	if _, err := d.DeriveTaskReflections(ctx, 0); !errors.Is(err, ErrMemoryInvalid) {
		t.Fatalf("task 0 should be refused, got %v", err)
	}
}

// TestGuardDenialsAreNotDefenceResponses: our own guard message says "blocked
// by the platform", so a run of denials must produce the opsec/denials
// reflection and NOT the target-defence heuristic.
func TestGuardDenialsAreNotDefenceResponses(t *testing.T) {
	d := memoryTestDB(t)
	ctx := context.Background()
	tk := memoryTask(t, d)
	es := d.Exploration(tk.ExplorationID)
	intentID, err := es.AddIntent(map[string]any{"summary": "denied work"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	blocked := "[ARTEX platform control - not target defense]This call was blocked by the platform. Reason: destructive command. This operation is forbidden."
	seedIntentActivity(t, es, intentID,
		[]Activity{{Tool: "Bash", Summary: "Bash rm -rf /srv"}, {Tool: "Write", Summary: "Write /etc/shadow"}, {Tool: "Bash", Summary: "Bash mkfs /dev/sda"}},
		[]Activity{
			{Tool: "Bash", IsError: true, Summary: blocked},
			{Tool: "Write", IsError: true, Summary: "This tool cannot be executed under intercept rule [no-writes]"},
			{Tool: "Bash", IsError: true, Summary: "A person denied execution"},
		})

	if n, err := d.DeriveIntentReflections(ctx, tk.ID, intentID); err != nil || n == 0 {
		t.Fatalf("created=%d err=%v", n, err)
	}
	if r := reflectionByKey(t, d, tk.ID, "intent:"+strconv.FormatInt(intentID, 10)+":guard-denials"); r == nil {
		t.Fatal("denial reflection missing")
	}
	if r := reflectionByKey(t, d, tk.ID, "intent:"+strconv.FormatInt(intentID, 10)+":defence-responses"); r != nil {
		t.Fatalf("guard denials were reported as target defences: %+v", r)
	}
}
