package db

import (
	"encoding/json"
	"testing"
)

// seedTestTool creates a system tool row under a per-test key and removes it
// afterwards, so these cases cannot collide with the real catalog or each other.
func seedTestTool(t *testing.T, d *DB, key, desc, schema string) {
	t.Helper()
	t.Cleanup(func() {
		d.Exec(`DELETE FROM tools WHERE key=$1`, key) //nolint:errcheck
	})
	if err := d.SeedTool(key, desc, json.RawMessage(schema), nil); err != nil {
		t.Fatalf("seed %s: %v", key, err)
	}
}

func mustTool(t *testing.T, d *DB, key string) *Tool {
	t.Helper()
	tool, err := d.GetTool(key)
	if err != nil {
		t.Fatalf("GetTool(%s): %v", key, err)
	}
	if tool == nil {
		t.Fatalf("GetTool(%s) returned no row", key)
	}
	return tool
}

// The defect: a description changed in code never reached an existing database.
func TestSeedToolPropagatesAChangedDescription(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	key := "zz_seedtest_propagate"
	seedTestTool(t, d, key, "first description", `{"type":"object"}`)
	if got := mustTool(t, d, key).Description; got != "first description" {
		t.Fatalf("description = %q", got)
	}

	if err := d.SeedTool(key, "second description", json.RawMessage(`{"type":"object"}`), nil); err != nil {
		t.Fatal(err)
	}
	if got := mustTool(t, d, key).Description; got != "second description" {
		t.Fatalf("a code change did not reach the row: description = %q", got)
	}
}

// The reason the old seed refused to overwrite: an operator edit must survive.
func TestSeedToolPreservesAnOperatorEdit(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	key := "zz_seedtest_edited"
	seedTestTool(t, d, key, "code default", `{"type":"object"}`)

	if err := d.UpdateTool(key, "operator wrote this", json.RawMessage(`{"type":"object"}`), nil, true); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedTool(key, "code default v2", json.RawMessage(`{"type":"object"}`), nil); err != nil {
		t.Fatal(err)
	}
	if got := mustTool(t, d, key).Description; got != "operator wrote this" {
		t.Fatalf("an operator edit was overwritten by a code change: %q", got)
	}
}

// Description and schema are tracked separately: editing one must not freeze the
// other, or a schema fix could never reach a row whose description was touched.
func TestSeedToolTracksDescriptionAndSchemaIndependently(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	key := "zz_seedtest_independent"
	seedTestTool(t, d, key, "code default", `{"type":"object","properties":{}}`)

	if err := d.UpdateTool(key, "operator wrote this", json.RawMessage(`{"type":"object","properties":{}}`), nil, true); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedTool(key, "code default v2",
		json.RawMessage(`{"type":"object","properties":{"limit":{"type":"number"}}}`), nil); err != nil {
		t.Fatal(err)
	}

	tool := mustTool(t, d, key)
	if tool.Description != "operator wrote this" {
		t.Errorf("edited description was overwritten: %q", tool.Description)
	}
	if !containsKey(tool.Schema, "limit") {
		t.Errorf("unedited schema did not pick up the new parameter: %s", tool.Schema)
	}
}

// Saving the edit form without changing the description must not orphan the row,
// or a no-op save would silently end code management for that tool.
func TestUpdateToolKeepsBaselineWhenNothingChanged(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	key := "zz_seedtest_noop"
	seedTestTool(t, d, key, "code default", `{"type":"object"}`)

	// Same description, new agent binding: an operator action, not an edit.
	if err := d.UpdateTool(key, "code default", json.RawMessage(`{"type":"object"}`), json.RawMessage(`["worker"]`), true); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedTool(key, "code default v2", json.RawMessage(`{"type":"object"}`), nil); err != nil {
		t.Fatal(err)
	}
	if got := mustTool(t, d, key).Description; got != "code default v2" {
		t.Fatalf("a no-op save orphaned the row: description = %q", got)
	}
}

// Reset is the way back from an edit: after it the row follows the code again.
func TestUpsertToolForceRestoresCodeManagement(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	key := "zz_seedtest_reset"
	seedTestTool(t, d, key, "code default", `{"type":"object"}`)
	if err := d.UpdateTool(key, "operator wrote this", json.RawMessage(`{"type":"object"}`), nil, true); err != nil {
		t.Fatal(err)
	}

	if err := d.UpsertToolForce(key, "code default", json.RawMessage(`{"type":"object"}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedTool(key, "code default v2", json.RawMessage(`{"type":"object"}`), nil); err != nil {
		t.Fatal(err)
	}
	if got := mustTool(t, d, key).Description; got != "code default v2" {
		t.Fatalf("a reset row does not follow the code again: %q", got)
	}
}

// Rows that predate the tracking have a NULL baseline. The backfill adopts their
// current value without changing it, and from then on a code change lands.
func TestBackfillAdoptsLegacyRowsThenTracksThem(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	key := "zz_seedtest_legacy"
	seedTestTool(t, d, key, "seeded long ago", `{"type":"object"}`)
	// Simulate a row written before the baseline columns existed.
	if _, err := d.Exec(`UPDATE tools SET seeded_description=NULL, seeded_schema=NULL WHERE key=$1`, key); err != nil {
		t.Fatal(err)
	}

	// Force the one-time backfill to run again.
	if _, err := d.Exec(`DELETE FROM settings WHERE key='tool_seed_baseline_backfilled_v1'`); err != nil {
		t.Fatal(err)
	}
	if err := d.BackfillToolSeedBaseline(); err != nil {
		t.Fatal(err)
	}
	if got := mustTool(t, d, key).Description; got != "seeded long ago" {
		t.Fatalf("the backfill changed a description: %q", got)
	}

	if err := d.SeedTool(key, "changed in code", json.RawMessage(`{"type":"object"}`), nil); err != nil {
		t.Fatal(err)
	}
	if got := mustTool(t, d, key).Description; got != "changed in code" {
		t.Fatalf("an adopted row still does not follow the code: %q", got)
	}
}

// Custom tools are operator-owned outright: the seed must never create or touch one.
func TestSeedToolDoesNotTouchCustomTools(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	key := "zz_seedtest_custom"
	// Clear first as well as after, so an interrupted earlier run cannot make this
	// test fail on a duplicate key rather than on what it asserts.
	if _, err := d.Exec(`DELETE FROM tools WHERE key=$1`, key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM tools WHERE key=$1`, key) }) //nolint:errcheck
	if err := d.CreateCustomTool(&Tool{
		Key: key, Description: "my own tool", Schema: json.RawMessage(`{"type":"object"}`),
		Agents: []string{"worker"}, Enabled: true, Kind: "command", Exec: json.RawMessage(`{"command":"true"}`),
	}); err != nil {
		t.Fatal(err)
	}

	if err := d.SeedTool(key, "code default", json.RawMessage(`{"type":"object"}`), nil); err != nil {
		t.Fatal(err)
	}
	tool := mustTool(t, d, key)
	if tool.Description != "my own tool" || tool.System {
		t.Fatalf("seed modified a custom tool: desc=%q system=%v", tool.Description, tool.System)
	}
}

func containsKey(raw json.RawMessage, key string) bool {
	var v map[string]any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	props, _ := v["properties"].(map[string]any)
	_, ok := props[key]
	return ok
}

// The sharp case: an operator edits a tool, then edits it back to the original
// text. Only a cleared baseline keeps that row safe. If the baseline survived the
// edit, the live text would match it again and the next seed would overwrite what
// the operator deliberately restored.
func TestSeedToolLeavesAnEditThatWasRevertedToTheOldText(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	key := "zz_seedtest_reverted"
	seedTestTool(t, d, key, "code default", `{"type":"object"}`)

	// Edit away, then restore the original text by hand.
	if err := d.UpdateTool(key, "something else", json.RawMessage(`{"type":"object"}`), nil, true); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateTool(key, "code default", json.RawMessage(`{"type":"object"}`), nil, true); err != nil {
		t.Fatal(err)
	}

	if err := d.SeedTool(key, "code default v2", json.RawMessage(`{"type":"object"}`), nil); err != nil {
		t.Fatal(err)
	}
	if got := mustTool(t, d, key).Description; got != "code default" {
		t.Fatalf("a reverted edit was overwritten; the edit did not clear its baseline: %q", got)
	}
}
