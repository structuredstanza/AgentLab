package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// mcpProtocolVersion is the MCP revision this server speaks; it matches the
// client side in mcphttp so the console can be both ends of the same protocol.
const mcpProtocolVersion = "2025-06-18"

// JSON-RPC 2.0 error codes. -32001 is MCP's "unauthorized"; the rest are the
// spec's standard set.
const (
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
	rpcUnauthorized   = -32001
)

// mcpMaxRows caps every list tool's output, and mcpSummaryChars caps one finding
// summary, so a harness cannot pull the whole engagement in one call.
const (
	mcpMaxRows      = 200
	mcpSummaryChars = 500
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpCallResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

// mcpTools is the complete read-only allow-list. tools/list returns exactly this
// set and tools/call refuses anything outside it, so the two cannot drift.
var mcpTools = []mcpTool{
	{
		Name:        "list_assets",
		Description: "List the assets in this token's task scope (id, type, value), up to 200.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
	{
		Name:        "get_asset",
		Description: "Fetch one asset of this token's task by id.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"id": map[string]any{"type": "integer", "description": "asset id"}},
			"required":   []string{"id"},
		},
	},
	{
		Name:        "list_findings",
		Description: "List this token's task findings (id, name, severity, status, summary), up to 200.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
	{
		Name:        "list_scope",
		Description: "List this token's task scope rows and its scope rules.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
}

func mcpToolAllowed(name string) bool {
	for _, t := range mcpTools {
		if t.Name == name {
			return true
		}
	}
	return false
}

// mcpRPC serves POST /mcp: JSON-RPC 2.0 over the four read tools, authenticated
// by a scoped API token only. It is mounted outside requireAuth on purpose: a
// JWT is not accepted here (AuthenticateAPIToken cannot resolve one), so an
// external harness can never hold the admin session.
func (s *Server) mcpRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	unauthorized := func() {
		writeJSON(w, http.StatusUnauthorized, mcpResponse{JSONRPC: "2.0", Error: &mcpError{rpcUnauthorized, "unauthorized"}})
	}
	plaintext, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || plaintext == "" {
		unauthorized()
		return
	}
	token, err := pg.AuthenticateAPIToken(r.Context(), plaintext)
	if err != nil {
		if errors.Is(err, db.ErrAPITokenInvalid) {
			unauthorized()
			return
		}
		writeJSON(w, http.StatusInternalServerError, mcpResponse{JSONRPC: "2.0", Error: &mcpError{rpcInternalError, "internal error"}})
		return
	}
	var req mcpRequest
	// The same ceiling as every other JSON route: params is buffered whole.
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", Error: &mcpError{rpcInvalidRequest, "invalid JSON"}})
		return
	}
	// A notification (no id, or an explicit null) is acknowledged without a body.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resp := mcpResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "m1nervac0nsole", "version": BuildVersion},
		}
	case "tools/list":
		resp.Result = map[string]any{"tools": mcpTools}
	case "tools/call":
		resp.Result, resp.Error = s.mcpCall(r.Context(), pg, token, req.Params)
	default:
		resp.Error = &mcpError{rpcMethodNotFound, "method not found: " + req.Method}
	}
	writeJSON(w, http.StatusOK, resp)
}

// mcpCall validates one tools/call, records its audit row and runs the tool. A
// tool that fails returns isError:true inside a normal result; only a request the
// protocol itself rejects becomes a JSON-RPC error.
func (s *Server) mcpCall(ctx context.Context, pg *db.DB, token *db.APIToken, raw json.RawMessage) (any, *mcpError) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, &mcpError{rpcInvalidParams, "invalid params"}
	}
	if !mcpToolAllowed(params.Name) {
		return nil, &mcpError{rpcInvalidParams, "unknown tool: " + params.Name}
	}
	args := params.Arguments
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	// One audit row per accepted call, written before the tool runs so a failing
	// tool is still on the record.
	if _, err := pg.ExecContext(ctx, `INSERT INTO mcp_audit(token_id, tool, args) VALUES ($1,$2,$3::jsonb)`,
		token.ID, params.Name, string(args)); err != nil {
		return nil, &mcpError{rpcInternalError, "audit failed"}
	}
	text, err := s.mcpRunTool(ctx, pg, token.TaskID, params.Name, args)
	if err != nil {
		return mcpCallResult{Content: []mcpContent{{Type: "text", Text: err.Error()}}, IsError: true}, nil
	}
	return mcpCallResult{Content: []mcpContent{{Type: "text", Text: text}}}, nil
}

func (s *Server) mcpRunTool(ctx context.Context, pg *db.DB, taskID int64, name string, raw json.RawMessage) (string, error) {
	switch name {
	case "list_assets":
		return mcpListAssets(ctx, pg, taskID, raw)
	case "get_asset":
		return mcpGetAsset(ctx, pg, taskID, raw)
	case "list_findings":
		return mcpListFindings(pg, taskID, raw)
	case "list_scope":
		return mcpListScope(pg, taskID)
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// mcpTaskArg reads the optional task_id argument. A caller may name a task, but
// only the token's own task is ever read: a mismatch yields false and the tool
// returns an empty result rather than an error, so the response cannot be used to
// probe which task ids exist.
func mcpTaskArg(raw json.RawMessage, taskID int64) (bool, error) {
	var args struct {
		TaskID int64 `json:"task_id"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return false, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	return args.TaskID == 0 || args.TaskID == taskID, nil
}

func mcpListAssets(ctx context.Context, pg *db.DB, taskID int64, raw json.RawMessage) (string, error) {
	ok, err := mcpTaskArg(raw, taskID)
	if err != nil {
		return "", err
	}
	type assetRow struct {
		ID    int64  `json:"id"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	out := []assetRow{}
	if ok {
		rows, err := pg.QueryContext(ctx, `SELECT id, type, COALESCE(url, domain, ip, app_name, root_domain, '')
FROM assets WHERE $1 = ANY(task_ids) ORDER BY id LIMIT $2`, taskID, mcpMaxRows)
		if err != nil {
			return "", fmt.Errorf("list assets: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a assetRow
			if err := rows.Scan(&a.ID, &a.Type, &a.Value); err != nil {
				return "", fmt.Errorf("list assets: %w", err)
			}
			out = append(out, a)
		}
		if err := rows.Err(); err != nil {
			return "", fmt.Errorf("list assets: %w", err)
		}
	}
	return marshalMCP(map[string]any{"assets": out})
}

func mcpGetAsset(ctx context.Context, pg *db.DB, taskID int64, raw json.RawMessage) (string, error) {
	var args struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}
	if args.ID <= 0 {
		return "", fmt.Errorf("id is required")
	}
	var (
		id         int64
		typ, value string
	)
	err := pg.QueryRowContext(ctx, `SELECT id, type, COALESCE(url, domain, ip, app_name, root_domain, '')
FROM assets WHERE id=$1 AND $2 = ANY(task_ids)`, args.ID, taskID).Scan(&id, &typ, &value)
	if errors.Is(err, sql.ErrNoRows) {
		// Another task's asset is indistinguishable from a missing one.
		return marshalMCP(map[string]any{"asset": nil})
	}
	if err != nil {
		return "", fmt.Errorf("get asset: %w", err)
	}
	return marshalMCP(map[string]any{"asset": map[string]any{"id": id, "type": typ, "value": value}})
}

func mcpListFindings(pg *db.DB, taskID int64, raw json.RawMessage) (string, error) {
	ok, err := mcpTaskArg(raw, taskID)
	if err != nil {
		return "", err
	}
	type findingRow struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Status   string `json:"status"`
		Summary  string `json:"summary"`
	}
	out := []findingRow{}
	if ok {
		rows, _, err := pg.ListFindingsPage(db.FindingFilter{TaskID: strconv.FormatInt(taskID, 10)}, 1, mcpMaxRows)
		if err != nil {
			return "", fmt.Errorf("list findings: %w", err)
		}
		for _, f := range rows {
			out = append(out, findingRow{f.ID, f.Name, f.Severity, f.Status, mcpTruncate(f.Summary)})
		}
	}
	return marshalMCP(map[string]any{"findings": out})
}

func mcpListScope(pg *db.DB, taskID int64) (string, error) {
	scopeRows, err := pg.Assets().ListTaskScopeWithSources(taskID)
	if err != nil {
		return "", fmt.Errorf("list scope: %w", err)
	}
	rules, err := pg.Assets().ListTaskScopeRuleRows(taskID)
	if err != nil {
		return "", fmt.Errorf("list scope rules: %w", err)
	}
	return marshalMCP(map[string]any{"scope": scopeRows, "rules": rules})
}

// mcpTruncate clips a summary to mcpSummaryChars runes, so a multi-byte character
// is never split.
func mcpTruncate(s string) string {
	if len(s) <= mcpSummaryChars {
		return s
	}
	r := []rune(s)
	if len(r) <= mcpSummaryChars {
		return s
	}
	return string(r[:mcpSummaryChars])
}

func marshalMCP(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode tool result: %w", err)
	}
	return string(b), nil
}
