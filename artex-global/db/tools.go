package db

import (
	"database/sql"
	"encoding/json"
)

// Tool is one row of the built-in tool catalog. key + handler live in code; this
// row carries only the page-editable surface: description, parameter schema
// (structure read-only, per-param description/default editable), agent binding,
// and the on/off switch. See schema.sql §H and agent/toolcatalog.go.
type Tool struct {
	Key         string          `json:"key"`
	System      bool            `json:"system"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Enabled     bool            `json:"enabled"`
	Kind        string          `json:"kind"`     // builtin | command | script | http
	Exec        json.RawMessage `json:"exec"`     // Custom tool execution spec (kind!=builtin)
	Deferred    bool            `json:"deferred"` // Deferred schema (goes through SearchExtraTools/ExecuteExtraTool)
	Calls       int             `json:"calls"`    // runtime ledger aggregate; not stored in tools
}

const toolCols = `key, system, description, schema, agents, enabled, kind, exec, deferred`

// SeedTool writes a built-in tool's code-defined description and schema, keeping
// any operator edit.
//
// A row records what the seed last wrote (seeded_description / seeded_schema). The
// seed overwrites a field only while the live value still equals its baseline, so a
// description or schema changed in code reaches an existing database on the next
// start, and a field the operator edited is left alone because UpdateTool clears its
// baseline. A NULL baseline means operator-owned and is never overwritten;
// UpsertToolForce restores it when the operator asks to reset to the code default.
//
// enabled and agents are operator state, not code defaults, and are never touched.
func (d *DB) SeedTool(key, desc string, schema, agents json.RawMessage) error {
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled, seeded_description, seeded_schema)
VALUES ($1, true, $2, $3, $4, true, $2, $3)
ON CONFLICT (key) DO UPDATE SET
  description        = CASE WHEN tools.seeded_description IS NOT NULL
                              AND tools.description = tools.seeded_description
                             THEN EXCLUDED.description ELSE tools.description END,
  seeded_description = CASE WHEN tools.seeded_description IS NOT NULL
                              AND tools.description = tools.seeded_description
                             THEN EXCLUDED.seeded_description ELSE tools.seeded_description END,
  schema             = CASE WHEN tools.seeded_schema IS NOT NULL
                              AND tools.schema = tools.seeded_schema
                             THEN EXCLUDED.schema ELSE tools.schema END,
  seeded_schema      = CASE WHEN tools.seeded_schema IS NOT NULL
                              AND tools.schema = tools.seeded_schema
                             THEN EXCLUDED.seeded_schema ELSE tools.seeded_schema END
WHERE tools.system`, key, desc, schema, agents)
	return err
}

// BackfillToolSeedBaseline gives every system tool row that predates seed tracking a
// baseline equal to its current description and schema, once.
//
// Without it, a row seeded before these columns existed would have a NULL baseline,
// read as operator-owned, and no code change would ever reach it again — the defect
// this tracking exists to fix. Adopting the current value changes nothing on this
// start and makes the next code change land. A description hand-edited before this
// version therefore becomes trackable, and a later code change may replace it; the
// reset action and version control are the recovery path.
func (d *DB) BackfillToolSeedBaseline() error {
	const flag = "tool_seed_baseline_backfilled_v1"
	if v, _, err := d.GetSetting(flag); err == nil && v == "true" {
		return nil
	}
	if _, err := d.Exec(`
UPDATE tools SET seeded_description = description, seeded_schema = schema
WHERE system AND seeded_description IS NULL AND seeded_schema IS NULL`); err != nil {
		return err
	}
	return d.SetSetting(flag, "true")
}

// AddAgentToToolBinding adds an agent key to the given tools' `agents` arrays if
// not already present (idempotent). Used to give the built-in Auto agent its
// default toolset on existing DBs.
func (d *DB) AddAgentToToolBinding(agentKey string, keys []string) error {
	for _, k := range keys {
		if _, err := d.Exec(`UPDATE tools SET agents = agents || to_jsonb($1::text) WHERE key=$2 AND NOT (agents ? $1)`, agentKey, k); err != nil {
			return err
		}
	}
	return nil
}

// RemoveAgentFromToolBindings strips an agent key from every tool's `agents`
// JSONB array — called when a custom agent is deleted so no tool keeps a dangling
// binding. Uses jsonb `-` (remove array element) guarded by `?` (membership).
func (d *DB) RemoveAgentFromToolBindings(agentKey string) error {
	_, err := d.Exec(`UPDATE tools SET agents = agents - $1 WHERE agents ? $1`, agentKey)
	return err
}

// RemoveAgentFromTool strips one agent key from a SINGLE tool's `agents` array —
// used by one-time migrations that change a tool's default binding on existing DBs
// (SeedTool is first-insert-only, so a changed default never reaches a seeded row).
func (d *DB) RemoveAgentFromTool(agentKey, toolKey string) error {
	_, err := d.Exec(`UPDATE tools SET agents = agents - $1 WHERE key=$2 AND agents ? $1`, agentKey, toolKey)
	return err
}

// UpsertToolForce overwrites a tool row with the given code-default values (used by
// the per-tool "reset" action). It resets description/schema/agents and re-enables
// the tool, but keeps system=true.
func (d *DB) UpsertToolForce(key, desc string, schema, agents json.RawMessage) error {
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled, seeded_description, seeded_schema)
VALUES ($1, true, $2, $3, $4, true, $2, $3)
ON CONFLICT (key) DO UPDATE
  SET description        = EXCLUDED.description,
      schema             = EXCLUDED.schema,
      agents             = EXCLUDED.agents,
      enabled            = true,
      seeded_description = EXCLUDED.seeded_description,
      seeded_schema      = EXCLUDED.seeded_schema`, key, desc, schema, agents)
	return err
}

func scanTool(rows interface{ Scan(...any) error }) (*Tool, error) {
	var t Tool
	var agents []byte
	if err := rows.Scan(&t.Key, &t.System, &t.Description, &t.Schema, &agents, &t.Enabled, &t.Kind, &t.Exec, &t.Deferred); err != nil {
		return nil, err
	}
	if len(agents) > 0 {
		_ = json.Unmarshal(agents, &t.Agents)
	}
	if t.Agents == nil {
		t.Agents = []string{}
	}
	return &t, nil
}

// ListTools returns the whole tool catalog, ordered by key.
func (d *DB) ListTools() ([]*Tool, error) {
	rows, err := d.Query(`SELECT ` + toolCols + ` FROM tools ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Tool
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTool fetches one tool row (nil if absent).
func (d *DB) GetTool(key string) (*Tool, error) {
	row := d.QueryRow(`SELECT `+toolCols+` FROM tools WHERE key=$1`, key)
	t, err := scanTool(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// CreateCustomTool inserts a user-defined tool (system=false) with an execution
// spec. Fails if the key already exists.
func (d *DB) CreateCustomTool(t *Tool) error {
	schema := t.Schema
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	exec := t.Exec
	if len(exec) == 0 {
		exec = json.RawMessage("{}")
	}
	agents, _ := json.Marshal(t.Agents)
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled, kind, exec, deferred)
VALUES ($1, false, $2, $3, $4, $5, $6, $7, $8)`,
		t.Key, t.Description, schema, agents, t.Enabled, t.Kind, exec, t.Deferred)
	return err
}

// UpdateCustomTool updates a custom tool's editable fields (kind/exec/deferred +
// desc/schema/agents/enabled). Only touches system=false rows.
func (d *DB) UpdateCustomTool(t *Tool) error {
	schema := t.Schema
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	exec := t.Exec
	if len(exec) == 0 {
		exec = json.RawMessage("{}")
	}
	agents, _ := json.Marshal(t.Agents)
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
UPDATE tools SET description=$2, schema=$3, agents=$4, enabled=$5, kind=$6, exec=$7, deferred=$8
WHERE key=$1 AND system=false`,
		t.Key, t.Description, schema, agents, t.Enabled, t.Kind, exec, t.Deferred)
	return err
}

// DeleteCustomTool removes a custom tool (system=false only; built-ins protected).
func (d *DB) DeleteCustomTool(key string) error {
	_, err := d.Exec(`DELETE FROM tools WHERE key=$1 AND system=false`, key)
	return err
}

// ListCustomTools returns only the user-defined (system=false) tools.
func (d *DB) ListCustomTools() ([]*Tool, error) {
	rows, err := d.Query(`SELECT ` + toolCols + ` FROM tools WHERE system=false ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Tool
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpdateTool saves the page-editable fields. key is never changed (it is welded to
// the Go handler). system tools: the caller must keep the schema structure — only
// per-param description/default and the agent binding are meant to move.
//
// A field the operator actually changed loses its seed baseline, so the next SeedTool
// leaves it alone; a field saved back unchanged keeps its baseline and stays under
// code management. Saving the form without editing must not orphan the row.
func (d *DB) UpdateTool(key, desc string, schema, agents json.RawMessage, enabled bool) error {
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
UPDATE tools SET description=$2, schema=$3, agents=$4, enabled=$5,
  seeded_description = CASE WHEN description IS DISTINCT FROM $2 THEN NULL ELSE seeded_description END,
  seeded_schema      = CASE WHEN schema      IS DISTINCT FROM $3 THEN NULL ELSE seeded_schema END
WHERE key=$1`,
		key, desc, schema, agents, enabled)
	return err
}
