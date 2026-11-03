package agent

import (
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// A long tool-heavy run writes several activity rows per turn. The planner's
// trigger context reads the worker's conclusion through workerOutput, which
// used to scan the OLDEST rows, so once the intent passed the row window the
// terminal result was outside it and the planner was told the worker had
// produced nothing.
func TestWorkerOutputKeepsTerminalResultPastTheRowWindow(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })

	var expID int64
	if err := d.QueryRow(`INSERT INTO explorations (description, goal) VALUES ('p','p') RETURNING id`).Scan(&expID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	ts := d.Exploration(expID)

	intentID, err := ts.AddIntent(map[string]any{"summary": "long run"}, 1, nil, "agent")
	if err != nil {
		t.Fatal(err)
	}
	// 350 turns x 3 rows = 1050, then the conclusion: just past the 1000-row window.
	for i := 0; i < 350; i++ {
		for _, kind := range []string{"tool_use", "tool_result", "usage"} {
			if _, err := ts.AppendActivity(db.Activity{
				NodeID: &intentID, Worker: "w", Kind: kind, Tool: "Bash",
				ToolUseID: fmt.Sprintf("t%d", i),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	const conclusion = "FINAL CONCLUSION: IDOR on /api/user"
	if _, err := ts.AppendActivity(db.Activity{
		NodeID: &intentID, Worker: "w", Kind: "result", Summary: "final", Detail: conclusion,
	}); err != nil {
		t.Fatal(err)
	}

	if got := workerOutput(ts, intentID); got != conclusion {
		t.Fatalf("workerOutput = %q, want the terminal conclusion", got)
	}
}
