package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/useragent"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/enrich"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/norma/permission"
	actool "github.com/structuredstanza/norma/tool"
)

// This file implements the custom tool executor (docs/\u81ea\u5b9a\u4e49\u5de5\u5177\u8bbe\u8ba1.md). Rows in tools with system=false are dispatched by
// kind: command (render the command, then reuse the low-level run of Bash), script (Python only; run inside the run's
// session, stdin = body + argument JSON, env TOOL_*, use the configured interpreter), http (native request with an optional proxy). These tools
// Like the traffic/orchestration tools, seed is not needed (they already live in the tools table); they are injected via hostTools and filtered by binding.

// ---------- Custom tool CRUD ----------

type customToolReq struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Enabled     bool            `json:"enabled"`
	Kind        string          `json:"kind"` // command | script | http
	Exec        json.RawMessage `json:"exec"`
	Deferred    bool            `json:"deferred"`
}

var reToolKey = reAgentKey // Same agent key rule: starts with a lowercase letter, followed by lowercase letters, digits, or underscores

// Validation errors returned by the custom tool management and trial-run endpoints.
const (
	errCustomToolKeyFormat          = "key must start with a lowercase letter and may contain only lowercase letters, digits, and underscores"
	errCustomToolKindInvalid        = "The kind value must be one of command, script, http, or shell"
	errCustomToolHTTPSchemaRequired = "The http tool requires a parameter JSON Schema (it cannot be empty)"
	errCustomToolKeyExists          = "This key already exists (built-in or custom tool)"
	errCustomToolEditCustomOnly     = "Only custom tools can be edited"
	errCustomToolBadBody            = "The request body is invalid"
	errCustomToolShellNoExec        = "A shell-type tool is a bash environment declaration, so there is nothing to execute"
	errCustomToolUnknownKindPrefix  = "Unknown tool type: "
	errCustomToolNoSession          = "The test run could not be given an isolated session, so nothing was executed: "
)

// createCustomTool is the one validate-and-insert path for a new custom tool,
// shared by POST /api/tools/custom and the tool curator's toolbox_propose_tool
// so a proposal can never store what the editor would refuse. It returns the
// HTTP status that fits the failure alongside the user-facing message.
func createCustomTool(pg *db.DB, req customToolReq) (int, error) {
	if !reToolKey.MatchString(req.Key) {
		return 400, errors.New(errCustomToolKeyFormat)
	}
	if req.Kind != "command" && req.Kind != "script" && req.Kind != "http" && req.Kind != "shell" {
		return 400, errors.New(errCustomToolKindInvalid)
	}
	if req.Kind == "http" && !hasSchemaProps(req.Schema) {
		return 400, errors.New(errCustomToolHTTPSchemaRequired)
	}
	if exist, _ := pg.GetTool(req.Key); exist != nil {
		return 409, errors.New(errCustomToolKeyExists)
	}
	if err := pg.CreateCustomTool(&db.Tool{
		Key: req.Key, Description: req.Description, Schema: req.Schema, Agents: req.Agents,
		Enabled: req.Enabled, Kind: req.Kind, Exec: req.Exec, Deferred: req.Deferred,
	}); err != nil {
		return 500, err
	}
	return 200, nil
}

func (s *Server) pgCreateCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req customToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Key = strings.TrimSpace(req.Key)
	if status, err := createCustomTool(pg, req); err != nil {
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"key": req.Key})
}

func (s *Server) pgUpdateCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	existing, err := pg.GetTool(key)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if existing == nil || existing.System {
		writeErr(w, 400, errCustomToolEditCustomOnly)
		return
	}
	var req customToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Kind != "command" && req.Kind != "script" && req.Kind != "http" && req.Kind != "shell" {
		writeErr(w, 400, errCustomToolKindInvalid)
		return
	}
	if req.Kind == "http" && !hasSchemaProps(req.Schema) {
		writeErr(w, 400, errCustomToolHTTPSchemaRequired)
		return
	}
	if err := pg.UpdateCustomTool(&db.Tool{
		Key: key, Description: req.Description, Schema: req.Schema, Agents: req.Agents,
		Enabled: req.Enabled, Kind: req.Kind, Exec: req.Exec, Deferred: req.Deferred,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) pgDeleteCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	if err := pg.DeleteCustomTool(key); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": key})
}

// testToolReq is a dry-run request from the editor: run the given (possibly unsaved)
// exec spec with sample params, without persisting the tool. Same executor path as a
// real tool call, under a short-lived session of its own.
type testToolReq struct {
	Kind   string          `json:"kind"` // command | script | http
	Exec   json.RawMessage `json:"exec"`
	Params map[string]any  `json:"params"`
	// TaskID binds the test run to an engagement task, so its session is judged
	// against that task's rules. Zero runs as research, which reaches no target.
	TaskID int64 `json:"task_id"`
}

// pgTestCustomTool executes an exec spec once and returns its raw output + error
// flag, so the editor can debug a tool before saving it. Per-kind timeouts still
// apply from the exec spec (with defaults); the outer ceiling is a hard backstop.
//
// A test is not a run, so it is given a session of its own: research by default,
// testing when the editor names a task. The credential is revoked when ctx ends,
// which covers completion, a client disconnect and the ceiling below, so a test
// leaves no live session behind. Without one a script or command would have no
// isolated boundary and an http request no recorded, authorized path.
func (s *Server) pgTestCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req testToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, errCustomToolBadBody)
		return
	}
	// The kind is checked before a session is minted: a request with nothing to
	// run must not leave a credential behind.
	switch req.Kind {
	case "command", "script", "http":
	case "shell":
		writeErr(w, 400, errCustomToolShellNoExec)
		return
	default:
		writeErr(w, 400, errCustomToolUnknownKindPrefix+req.Kind)
		return
	}
	params := req.Params
	if params == nil {
		params = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	purpose := netpolicy.PurposeResearch
	if req.TaskID > 0 {
		purpose = netpolicy.PurposeTesting
	}
	sess, err := s.session(ctx, netpolicy.CallerChat, req.TaskID, 0, purpose)
	if err != nil {
		writeErr(w, 409, errCustomToolNoSession+err.Error())
		return
	}
	ctx = execbox.WithSession(ctx, sess)
	// The session's private /tmp: the backend's own directory is not a writable
	// root, so a spawn there is refused. The env is the run's proxy env, so a
	// script's HTTP is recorded and authorized like a real call's.
	tc := &actool.ToolContext{Env: agent.ProxyEnv(netpolicy.ProxyURL(sess, s.m.ProxyAddr()), s.m.ProxyCACert())}
	var res actool.Result
	switch req.Kind {
	case "command":
		res, _ = s.runCommandTool(ctx, req.Exec, params, tc)
	case "script":
		res, _ = s.runScriptTool(ctx, "test", req.Exec, params, tc)
	case "http":
		// The editor has no direct path to an origin: the test request goes
		// through the recording proxy of the session above, and is refused when
		// none is reachable.
		res, _ = s.runHTTPTool(ctx, req.Exec, params, tc)
	}
	writeJSON(w, 200, map[string]any{"output": res.Flatten(), "is_error": res.IsError})
}

// ---------- Python interpreter (detection + registration + override) ----------

const settingPythonInterp = "python_interpreter"

// detectPython finds a python interpreter absolute path (python3 preferred).
func detectPython() string {
	for _, c := range []string{"python3", "python"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// pythonInterpreter resolves the interpreter: user-set > stored auto-detect > live
// detect. "" only when truly none found.
func (s *Server) pythonInterpreter() string {
	if v, ok, _ := s.m.pg.GetSetting(settingPythonInterp); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return detectPython()
}

// seedPythonInterpreter stores the auto-detected interpreter on startup if unset
// (never clobbers a user-set value).
func (s *Server) seedPythonInterpreter() {
	if v, ok, _ := s.m.pg.GetSetting(settingPythonInterp); ok && strings.TrimSpace(v) != "" {
		return
	}
	if p := detectPython(); p != "" {
		_ = s.m.pg.SetSetting(settingPythonInterp, p)
		log.Printf("[custom-tool] auto-detected python interpreter: %s", p)
	}
}

// ---------- exec spec ----------

type commandExec struct {
	Command   string `json:"command"`
	TimeoutMs int    `json:"timeout_ms"`
}
type scriptExec struct {
	Code      string `json:"code"`
	TimeoutMs int    `json:"timeout_ms"`
}
type httpExec struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	TimeoutMs int               `json:"timeout_ms"`
}

func timeoutOr(ms, def int) time.Duration {
	if ms <= 0 {
		return time.Duration(def) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

// ---------- General tool construction ----------

// customTools builds CoreTools for every user-defined (system=false) tool row.
// shell-kind tools are environment hints only — they surface in the Bash tool
// description via ToolResolve and do NOT create callable tool entries here.
func (s *Server) customTools() ([]actool.CoreTool, error) {
	rows, err := s.m.pg.ListCustomTools()
	if err != nil {
		return nil, err
	}
	out := make([]actool.CoreTool, 0, len(rows))
	for _, t := range rows {
		if t.Kind == "shell" {
			continue // shell hints are handled by ToolResolve → Bash description
		}
		out = append(out, s.buildCustomTool(t))
	}
	return out, nil
}

// buildCustomTool turns one custom-tool row into a CoreTool. Empty schema → a thin
// {args:string} (thin-wrapper tool), so command/http templates can use {args}.
func (s *Server) buildCustomTool(t *db.Tool) actool.CoreTool {
	schema := ensureSchema(t.Schema)
	key, kind, execRaw := t.Key, t.Kind, t.Exec
	run := func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
		var params map[string]any
		if len(in) > 0 {
			_ = json.Unmarshal(in, &params)
		}
		if params == nil {
			params = map[string]any{}
		}
		switch kind {
		case "command":
			return s.runCommandTool(ctx, execRaw, params, tc)
		case "script":
			return s.runScriptTool(ctx, key, execRaw, params, tc)
		case "http":
			return s.runHTTPTool(ctx, execRaw, params, tc)
		default:
			return actool.Errorf("unknown custom tool type: " + kind), nil
		}
	}
	return actool.Build(actool.Spec{
		Name: key, Description: t.Description, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: run,
	})
}

// hasSchemaProps reports whether raw is a JSON-Schema object with ≥1 property.
// http tools require an explicit schema (the auto {args} shell can't name the
// {param} placeholders in URL/headers/body), so an empty schema is rejected.
func hasSchemaProps(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	props, _ := m["properties"].(map[string]any)
	return len(props) > 0
}

// ensureSchema returns the tool's schema, or a thin {args:string} when none given.
func ensureSchema(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	props, _ := m["properties"].(map[string]any)
	if len(props) > 0 {
		return m
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"args": map[string]any{"type": "string", "description": "command/arguments (free text)"},
		},
	}
}

// ---------- command: render command → reuse Bash underlying run ----------

func (s *Server) runCommandTool(ctx context.Context, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec commandExec
	_ = json.Unmarshal(execRaw, &spec)
	if strings.TrimSpace(spec.Command) == "" {
		return actool.Errorf("command is empty"), nil
	}
	cmd := renderTemplate(spec.Command, params, shellQuote)
	// Reuses the underlying run() that Bash also uses (via Bash CoreTool.Call): automatically inherits the security floor/timeout/
	// Proxy env/output overflow. The tool is at the same level as Bash and shares the underlying layer; it is not invoked by the model through the Bash tool.
	bashIn, _ := json.Marshal(map[string]any{"command": cmd})
	if spec.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 120000))
		defer cancel()
	}
	return actool.NewBash().Call(ctx, bashIn, tc)
}

// ---------- script (Python only): session + stdin body + env ----------

// What one script tool call may deliver. The body travels on stdin, so it no
// longer competes with ARG_MAX; a TOOL_<NAME> entry is an execve environment
// string, so it has to stay under the kernel's per-string limit or the spawn
// fails with E2BIG instead of a message the model can act on.
const (
	maxScriptBytes  = 1 << 20   // the body, buffered once by this backend
	maxToolEnvBytes = 128 << 10 // MAX_ARG_STRLEN, per "TOOL_<NAME>=<value>"
	maxToolEnvTotal = 1 << 20   // the whole TOOL_* set, well inside ARG_MAX
)

// scriptBootstrap is the fixed program a script tool starts. It copies the body
// from stdin into the file named on its command line, then runs the interpreter
// on that file. Neither the body nor the params therefore reach argv, which the
// guest records, and a body larger than ARG_MAX still runs. The params follow
// the body on the same stream, so a script keeps reading its JSON from stdin.
const scriptBootstrap = `d=$(dirname "$2") && mkdir -p "$d" && (umask 077 && head -c "$1" > "$2") && exec "$3" "$2"`

// runScriptTool runs a custom Python tool inside the run's isolated session, the
// boundary the command kind already gets through Bash. A fixed bootstrap takes
// the body and the params on stdin, writes the body into the session's working
// directory and executes it, so a script still reads its params from stdin JSON
// and TOOL_<NAME> and never sees the backend's own environment. stdin EOF
// follows the write, so a script that reads its params to EOF finishes instead
// of hanging.
//
// There is no direct-execution fallback: without an installed client or without
// a session the call refuses, so a script tool can never run as root in the
// backend's network namespace.
func (s *Server) runScriptTool(ctx context.Context, key string, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec scriptExec
	_ = json.Unmarshal(execRaw, &spec)
	if strings.TrimSpace(spec.Code) == "" {
		return actool.Errorf("script code is empty"), nil
	}
	if len(spec.Code) > maxScriptBytes {
		return actool.Errorf(fmt.Sprintf("script code is %d bytes; the limit is %d", len(spec.Code), maxScriptBytes)), nil
	}
	client, ok := execbox.Installed()
	if !ok {
		return actool.Errorf(fmt.Sprintf("%v: no execution client is installed, so the script was not started", execbox.ErrUnavailable)), nil
	}
	sess, err := execbox.RequireSession(ctx)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	interp := s.pythonInterpreter()
	if interp == "" {
		return actool.Errorf("no Python interpreter is configured or detected (set one in system settings)"), nil
	}
	// The working directory mirrors the command kind: the tool context's, and the
	// session's private /tmp when it names none.
	workDir := "/tmp"
	var sessionEnv []string
	if tc != nil {
		if tc.WorkingDir != "" {
			workDir = tc.WorkingDir
		}
		sessionEnv = tc.Env
	}
	env, err := scriptEnv(sessionEnv, params)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	script := scriptPath(workDir, key, spec.Code)
	runCtx, cancel := context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 120000))
	defer cancel()
	if tc != nil {
		runCtx = execbox.WithArtifacts(runCtx, execbox.ArtifactCall{Dir: tc.WorkingDir, ToolUseID: tc.ToolUseID})
	}
	rwc, err := client.Run(runCtx, sess, execbox.Spec{
		Argv:        scriptArgv(interp, key, script, len(spec.Code)),
		Dir:         workDir,
		Env:         env,
		MergeStderr: true,
	})
	if err != nil {
		if errors.Is(err, execbox.ErrUnavailable) {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text(actool.Capture(tc, "[exit: "+err.Error()+"]")), nil
	}
	proc, ok := execbox.ProcessOf(rwc)
	if !ok {
		_ = rwc.Close()
		return actool.Errorf("the execution client cannot signal stdin EOF, so the script was not started"), nil
	}
	defer proc.Close()
	// The body goes first, exactly the bytes the bootstrap copies to the script
	// file, then the params JSON the script reads. The write runs beside the
	// output drain: a body larger than the socket buffer must not wait on a
	// program whose output nobody is reading yet.
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		_, _ = proc.Write([]byte(spec.Code))
		pj, _ := json.Marshal(params)
		_, _ = proc.Write(pj)
		_ = proc.CloseStdin()
	}()
	var out bytes.Buffer
	_, _ = io.Copy(&out, proc)
	select {
	case <-stdinDone:
	case <-runCtx.Done():
	}
	code, waitErr := proc.Wait()
	body := out.String()
	switch {
	case runCtx.Err() == context.DeadlineExceeded:
		body += "\n... [terminated on timeout] ..."
	case waitErr != nil:
		body += "\n[exit: " + waitErr.Error() + "]"
	case code != 0:
		body += fmt.Sprintf("\n[exit: exit status %d]", code)
	}
	// The file is the record of what ran: the export carries the workspace, and
	// the turn's tool result names the exact path. The capture pointer names the
	// process's own stdin and output, which the workspace file does not hold.
	body += "\n[script: " + script + "]"
	return actool.Text(actool.Capture(tc, withArtifactRef(body, execbox.ArtifactPointer(proc)))), nil
}

// scriptArgv starts the fixed bootstrap with the body's byte length, the file it
// must land in and the interpreter to run. No content travels in argv, which the
// guest records; $0 is the tool key, so the process is identifiable.
func scriptArgv(interp, key, file string, bodyLen int) []string {
	return []string{"bash", "-c", scriptBootstrap, key, strconv.Itoa(bodyLen), file, interp}
}

// scriptPath is where the bootstrap writes the body inside the session: a
// content-addressed file under the run's working directory, so the export
// carries exactly the bytes that ran and the name doubles as an integrity check.
func scriptPath(workDir, key, code string) string {
	sum := sha256.Sum256([]byte(code))
	return path.Join(workDir, ".tool-scripts", key+"-"+hex.EncodeToString(sum[:8])+".py")
}

// scriptEnv is the minimal environment a script tool runs with: the run's own
// proxy env plus the scalar params mirrored to TOOL_<NAME>. The backend's
// environment is deliberately absent, so a controller secret cannot reach a
// script through an unrelated variable. The supervisor adds PATH/HOME/TMPDIR.
// A parameter too large for an environment string is refused here, where the
// caller can say which one, instead of failing the spawn with E2BIG.
func scriptEnv(sessionEnv []string, params map[string]any) ([]string, error) {
	env := append([]string(nil), sessionEnv...)
	total := 0
	for k, v := range params {
		sv, ok := scalarStr(v)
		if !ok {
			continue
		}
		kv := "TOOL_" + strings.ToUpper(k) + "=" + sv
		if len(kv) >= maxToolEnvBytes {
			return nil, fmt.Errorf("parameter %q is too large for the script environment (%d bytes; the limit is %d)", k, len(kv), maxToolEnvBytes-1)
		}
		if total += len(kv); total > maxToolEnvTotal {
			return nil, fmt.Errorf("the script parameters are too large for the script environment (%d bytes; the limit is %d)", total, maxToolEnvTotal)
		}
		env = append(env, kv)
	}
	return env, nil
}

// ---------- http: native request + proxy ----------

func (s *Server) runHTTPTool(ctx context.Context, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec httpExec
	_ = json.Unmarshal(execRaw, &spec)
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = "GET"
	}
	rawURL := renderTemplate(spec.URL, params, identity)
	if strings.TrimSpace(rawURL) == "" {
		return actool.Errorf("http url is empty"), nil
	}
	var bodyReader io.Reader
	if spec.Body != "" {
		bodyReader = strings.NewReader(renderTemplate(spec.Body, params, identity))
	}
	runCtx, cancel := context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 30000))
	defer cancel()
	req, err := http.NewRequestWithContext(runCtx, method, rawURL, bodyReader)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	for k, v := range spec.Headers {
		req.Header.Set(k, renderTemplate(v, params, identity))
	}
	useragent.SetIfAbsent(req.Header.Set, req.Header.Get("User-Agent"))
	client := &http.Client{Timeout: timeoutOr(spec.TimeoutMs, 30000)}
	tr, revoke, err := s.httpProxyTransport(ctx)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	defer revoke()
	client.Transport = tr
	resp, err := client.Do(req)
	if err != nil {
		return actool.Errorf("request failed: " + err.Error()), nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := map[string]any{"status": resp.StatusCode, "body": string(respBody)}
	b, _ := json.Marshal(out)
	return actool.Text(actool.Capture(tc, string(b))), nil
}

// httpProxyTransport builds the Transport every http tool call uses: the
// recording proxy under the run's own gateway session, trusting the recorder's
// CA. A run with no task session gets a research session instead. It never
// returns a transport that can dial a target directly: with no session and no
// recording proxy, or a CA that cannot be loaded, the call fails. The tool's
// former "proxy" field is gone because it bypassed the gateway. revoke ends a
// research session's credential and is never nil.
func (s *Server) httpProxyTransport(ctx context.Context) (tr *http.Transport, revoke func(), err error) {
	proxyStr, caFile := execbox.ProxyURL(ctx, s.m.ProxyAddr()), s.m.ProxyCACert()
	revoke = func() {}
	if proxyStr == "" {
		var rev func()
		if proxyStr, caFile, rev, err = s.researchProxy(ctx); err != nil {
			return nil, nil, err
		}
		if rev != nil {
			revoke = rev
		}
	}
	fail := func(e error) (*http.Transport, func(), error) { revoke(); return nil, nil, e }
	if proxyStr == "" {
		return fail(fmt.Errorf("this run has no gateway session or no recording proxy is running; refusing to send the request directly"))
	}
	pu, err := url.Parse(proxyStr)
	if err != nil || pu.Host == "" {
		return fail(fmt.Errorf("invalid proxy URL %q", enrich.RedactProxyURL(proxyStr)))
	}
	tr = &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return fail(fmt.Errorf("recorder CA unreadable, refusing to fall back to default roots: %w", err))
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fail(fmt.Errorf("recorder CA %s holds no certificate, refusing to fall back to default roots", caFile))
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return tr, revoke, nil
}

// ---------- helpers ----------

func identity(s string) string { return s }

// shellQuote single-quotes a value for safe shell interpolation.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// renderTemplate replaces {name} placeholders with each param's rendered value.
func renderTemplate(tmpl string, params map[string]any, quote func(string) string) string {
	out := tmpl
	for k, v := range params {
		out = strings.ReplaceAll(out, "{"+k+"}", quote(valToStr(v)))
	}
	return out
}

// valToStr renders a param value: scalars as-is, arrays/objects as compact JSON.
func valToStr(v any) string {
	if sv, ok := scalarStr(v); ok {
		return sv
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// scalarStr returns (string, true) for scalar values, ("", false) for arrays/objects.
func scalarStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return fmt.Sprintf("%t", x), true
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x)), true
		}
		return fmt.Sprintf("%g", x), true
	case nil:
		return "", true
	default:
		return "", false
	}
}
