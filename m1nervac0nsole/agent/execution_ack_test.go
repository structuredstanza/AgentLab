package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	actool "github.com/structuredstanza/norma/tool"
)

func callTool(t *testing.T, tool actool.CoreTool, in string) (string, bool) {
	t.Helper()
	res, err := tool.Call(context.Background(), json.RawMessage(in), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Flatten(), res.IsError
}

// A failed task admission must surface as an error result, single or batch, while
// the intents it created stay stored: they are real, they just will not run yet.
func TestAddIntentAdmissionFailureIsErrorAndKeepsIntents(t *testing.T) {
	ts := hintTestStore(t)
	tools := NewToolSet(ts, "human")
	tools.SetResumeTask(func() (string, error) { return "", errors.New("task is being deleted") })

	if _, isErr := callTool(t, tools.addIntent(), `{"summary":"single"}`); !isErr {
		t.Fatal("single add_intent with failed admission must be an error result")
	}
	out, isErr := callTool(t, tools.addIntent(), `{"intents":[{"summary":"a"},{"summary":"b"}]}`)
	if !isErr {
		t.Fatal("batch add_intent with failed admission must be an error result")
	}
	var parsed struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil || len(parsed.IDs) != 2 {
		t.Fatalf("batch error must still carry the created ids: %q %v", out, err)
	}
	open, err := ts.ListByKindState("intent", "open", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 3 {
		t.Fatalf("intents must survive a failed admission, got %d open", len(open))
	}
}

func TestAddIntentAdmissionSuccessIsNotAnError(t *testing.T) {
	tools := NewToolSet(hintTestStore(t), "human")
	tools.SetResumeTask(func() (string, error) { return "queued", nil })
	if out, isErr := callTool(t, tools.addIntent(), `{"intents":[{"summary":"a"}]}`); isErr {
		t.Fatalf("admitted intents must not be an error: %q", out)
	}
}

// kill_work may only report success when the engine confirmed the worker is gone
// AND the intent is no longer recorded as running.
func TestKillWorkToolRefusesUnconfirmedStop(t *testing.T) {
	ts := hintTestStore(t)
	tools := NewToolSet(ts, "human")
	id, err := ts.AddIntent(map[string]any{"summary": "running"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ts.CompareAndSetIntentState(id, "open", "running"); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	in := `{"intent_id":` + strconv.FormatInt(id, 10) + `,"reason":"operator stop"}`

	tools.SetKillWork(func(context.Context, int64, int64, string) error { return errors.New("worker had not finished") })
	if _, isErr := callTool(t, tools.killWorkTool(), in); !isErr {
		t.Fatal("an engine error must not be reported as a stop")
	}

	tools.SetKillWork(func(context.Context, int64, int64, string) error { return nil })
	if _, isErr := callTool(t, tools.killWorkTool(), in); !isErr {
		t.Fatal("an intent still recorded as running must not be reported as stopped")
	}
}
