package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	pgdb "github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/limits"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/norma/permission"
	actool "github.com/structuredstanza/norma/tool"
)

// builtinManifests is the shipped set, parsed once. It is the live set until
// the stored overlay has been read, and the base every overlay is built on.
var builtinManifests = manifest.LoadBuiltin()

// manifestSnapshot is one consistent view of the catalog: the effective set and
// the stored TOML that produced its overrides. Only rows that passed Check are
// in stored, so a broken row is reported as the built-in it failed to replace.
type manifestSnapshot struct {
	set    *manifest.Set
	stored map[string]string
}

// liveManifestSet publishes the current snapshot. Readers (run_tool, list_tools,
// the HTTP handlers) never take the mutex; it only orders concurrent reloads so
// an older database read cannot overwrite a newer one.
type liveManifestSet struct {
	mu   sync.Mutex
	snap atomic.Pointer[manifestSnapshot]
}

// manifests returns the live tool set: built-ins plus stored overrides and
// custom templates.
func (s *Server) manifests() *manifest.Set {
	if snap := s.manifestLive.snap.Load(); snap != nil {
		return snap.set
	}
	return builtinManifests
}

// reloadManifests rebuilds the live set from the built-ins and the stored rows.
// A stored row that fails Check is skipped and logged: one bad template must
// never hide the shipped tools or the other templates.
func (s *Server) reloadManifests(ctx context.Context) error {
	live := &s.manifestLive
	live.mu.Lock()
	defer live.mu.Unlock()
	rows, err := s.m.pg.ListToolManifests(ctx)
	if err != nil {
		return err
	}
	snap := &manifestSnapshot{stored: map[string]string{}}
	extra := make([]*manifest.Manifest, 0, len(rows))
	for _, r := range rows {
		m, err := manifest.Check(r.TOML)
		if err != nil {
			log.Printf("[manifests] skipping stored template %q: %v", r.ID, err)
			continue
		}
		extra = append(extra, m)
		snap.stored[m.ID] = r.TOML
	}
	snap.set = builtinManifests.Overlay(extra)
	live.snap.Store(snap)
	return nil
}

// manifestInvalidError marks a template the operator can fix, so the handler
// answers 400 while a database failure stays a 500. The message is Check's own.
type manifestInvalidError struct{ error }

func (e manifestInvalidError) Unwrap() error { return e.error }

// saveManifest validates a template, stores it under the id it declares and
// reloads the live set. Saving a built-in's id overrides it; deleting the row
// restores the shipped one.
func (s *Server) saveManifest(ctx context.Context, toml string) (string, error) {
	m, err := manifest.Check(toml)
	if err != nil {
		return "", manifestInvalidError{err}
	}
	if s.m.pg == nil {
		return "", errors.New("database unavailable")
	}
	if err := s.m.pg.UpsertToolManifest(ctx, m.ID, toml); err != nil {
		return "", err
	}
	if err := s.reloadManifests(ctx); err != nil {
		return "", err
	}
	return m.ID, nil
}

// manifestSource reports a template's TOML and where it comes from: builtin
// (as shipped), modified (a stored override of a built-in) or custom (stored,
// no built-in of that id).
func (s *Server) manifestSource(id string) (toml string, source string, ok bool) {
	if snap := s.manifestLive.snap.Load(); snap != nil {
		if text, found := snap.stored[id]; found {
			if _, shipped := manifest.BuiltinSource(id); shipped {
				return text, "modified", true
			}
			return text, "custom", true
		}
	}
	text, shipped := manifest.BuiltinSource(id)
	return text, "builtin", shipped
}

// engagementLimits bounds simultaneous tool runs, not their rates or threads.
var engagementLimits = limits.New(policyFromEnv())

// policyFromEnv lets an operator change the ceilings for one engagement without
// rebuilding: the defaults are a shared lab's, and a dedicated box can take more.
func policyFromEnv() limits.Policy {
	p := limits.DefaultLabPolicy()
	if v, err := strconv.Atoi(os.Getenv("M1NERVAC0NSOLE_MAX_CONCURRENT_SCANS")); err == nil && v > 0 {
		p.MaxConcurrentTotal = v
	}
	if v, err := strconv.Atoi(os.Getenv("M1NERVAC0NSOLE_MAX_SCANS_PER_TARGET")); err == nil && v > 0 {
		p.MaxConcurrentPerTarget = v
	}
	return p
}

// toolManifest is the DTO the tool list and the run form both render, so the UI
// and the executor read the same declaration.
type toolManifest struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Category    string                    `json:"category"`
	Accepts     []string                  `json:"accepts"`
	Requires    []string                  `json:"requires"`
	Available   bool                      `json:"available"`
	Params      map[string]manifest.Param `json:"params"`
	Timeout     int                       `json:"timeout_seconds"`
	Source      string                    `json:"source"`
	TOML        string                    `json:"toml"`
	Installable bool                      `json:"installable"`
	// Artifact is the binary an install published into the persistent toolbox,
	// read from that directory on every list. It is absent when nothing was
	// published, so a row that never installed carries no claim about PATH.
	Artifact *toolArtifact `json:"artifact,omitempty"`
}

func (s *Server) listToolManifests(w http.ResponseWriter, r *http.Request) {
	set := s.manifests()
	out := make([]toolManifest, 0, set.Len())
	for _, m := range set.All() {
		toml, source, _ := s.manifestSource(m.ID)
		accepts := make([]string, len(m.Accepts))
		for i, k := range m.Accepts {
			accepts[i] = string(k)
		}
		out = append(out, toolManifest{
			ID:          m.ID,
			Name:        m.Name,
			Description: m.Description,
			Category:    string(m.Category),
			Accepts:     accepts,
			Requires:    m.Requires,
			// Available is reported, not enforced: a tool absent from the image
			// still has a valid manifest, and the operator should see which of
			// the declared tools this build can actually run.
			Available: binaryPresent(m.Requires),
			Params:    m.Params,
			Timeout:   m.Command.TimeoutSeconds,
			Source:    source,
			TOML:      toml,
			// Installable is what the Toolbox keys its Install button on.
			Installable: m.Install.Script != "",
			Artifact:    publishedArtifact(m.Command.Program),
		})
	}
	writeJSON(w, 200, map[string]any{"tools": out})
}

// binaryPresent reports whether every named binary is runnable: on the backend's
// own PATH, or in the persistent toolbox bin directory, which is on every
// session's PATH. A tool the supervisor published is available to a run even
// though the backend's PATH does not include that directory.
func binaryPresent(bins []string) bool {
	for _, b := range bins {
		if _, err := exec.LookPath(b); err == nil {
			continue
		}
		fi, err := os.Stat(filepath.Join(execbox.ToolboxRoot(), "bin", b))
		if err != nil || !fi.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// toolArtifact is the published binary in the persistent toolbox bin directory:
// where it is, how big it is, when it was published and its digest. It is read
// from the file, so it describes what PATH actually resolves to rather than what
// an install reported at the time.
type toolArtifact struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	InstalledAt string `json:"installed_at"`
}

// artifactDigest caches one file's digest against the size and mtime it was
// computed from, so listing the catalog does not rehash every installed tool.
type artifactDigest struct {
	size    int64
	modTime time.Time
	sha256  string
}

var artifactDigests sync.Map // path -> artifactDigest

// publishedArtifact reports what the supervisor published for a program, or nil
// when it published nothing: a manifest that was never installed, a template
// whose program is an absolute path (which publishes outside the staging
// prefix), or a bin directory this process cannot read.
func publishedArtifact(program string) *toolArtifact {
	if program == "" || strings.ContainsRune(program, '/') {
		return nil
	}
	path := filepath.Join(execbox.ToolboxRoot(), "bin", program)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	sum := ""
	if cached, ok := artifactDigests.Load(path); ok {
		if d, ok := cached.(artifactDigest); ok && d.size == fi.Size() && d.modTime.Equal(fi.ModTime()) {
			sum = d.sha256
		}
	}
	if sum == "" {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil
		}
		sum = fmt.Sprintf("%x", h.Sum(nil))
		artifactDigests.Store(path, artifactDigest{size: fi.Size(), modTime: fi.ModTime(), sha256: sum})
	}
	return &toolArtifact{
		Path:        path,
		Size:        fi.Size(),
		SHA256:      sum,
		InstalledAt: fi.ModTime().UTC().Format(time.RFC3339),
	}
}

// previewToolManifest renders the argv the executor would run, without running
// it. Both paths call the same resolver (Effective then Resolve), so a preview
// cannot drift from execution; the only difference is that the executor also
// checks scope and the rate gate first.
func (s *Server) previewToolManifest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("key")
	m := s.manifests().Get(id)
	if m == nil {
		writeErr(w, 404, fmt.Sprintf("unknown tool %q", id))
		return
	}
	var req struct {
		Target string         `json:"target"`
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		writeErr(w, 400, "target is required")
		return
	}
	params, err := paramStrings(req.Params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	effective, err := m.Effective(params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// The preview runs outside any session and is shown in the UI, so it renders
	// no proxy: a credential must never reach an API response. Execution passes
	// the run's own proxy URL, which is why the preview can differ in that one
	// argument.
	args, err := m.Resolve(req.Target, effective, "")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"program":   m.Command.Program,
		"args":      args,
		"effective": effective,
		"available": binaryPresent(m.Requires),
	})
}

// toolRunManifest executes one manifest-backed tool and returns the parsed
// records plus the assets and facts its emit rules produced.
//
// The tool is invoked without a shell, so a parameter containing a space stays
// one argument and no operator input can be read as a shell metacharacter.
func (s *Server) toolRunManifest() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "run_tool",
		Description: "Run a reconnaissance or scanning tool declared by a manifest, and return its parsed records, the assets it found and the facts it recorded. Call list_tools first for the operator's speed profile and the parameters each tool accepts. Prefer this over Bash for any tool that appears in the list: the manifest pins the flags, parses the output into assets, and refuses an out-of-scope target.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tool": map[string]any{
					"type":        "string",
					"description": "Manifest id, for example nmap, nuclei or ffuf",
				},
				"target": map[string]any{
					"type":        "string",
					"description": "Asset to run against: a host, an IP, a CIDR or a URL",
				},
				"params": map[string]any{
					"type":        "object",
					"description": "Tool parameters, keyed by the names list_tools reports. Values may be strings, numbers or true/false",
				},
			},
			"required": []string{"tool", "target"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Tool   string         `json:"tool"`
				Target string         `json:"target"`
				Params map[string]any `json:"params"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(fmt.Sprintf("bad input: %v", err)), nil
			}
			params, err := paramStrings(in.Params)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("bad input: %v", err)), nil
			}
			m := s.manifests().Get(in.Tool)
			if m == nil {
				return actool.Errorf(fmt.Sprintf("unknown tool %q; call list_tools for the manifest ids", in.Tool)), nil
			}
			// Enforce the task boundary here, on the resolved target.
			//
			// The description promises this, and until now nothing did it: the
			// guard's text scan runs over the raw tool-call arguments, which is
			// a different question from "is this host excluded". A manifest tool
			// names its target as a first-class field, so the answer is exact
			// rather than inferred — this is the strongest place to check it.
			if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
				if checker := pgdb.NewTaskScopeChecker(s.m.Assets(), ri.TaskID); checker != nil {
					if out, reason := checker.Judge(in.Target); out {
						return actool.Errorf(fmt.Sprintf("out of scope: %s — %s", in.Target, reason)), nil
					}
				}
			}
			if !binaryPresent(m.Requires) {
				return actool.Errorf(fmt.Sprintf("%s is declared but not installed in this environment (needs %s)",
					in.Tool, strings.Join(m.Requires, ", "))), nil
			}
			effective, err := m.Effective(params)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			release, err := engagementLimits.Acquire(ctx, in.Target, m, effective)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%s not started: %v", in.Tool, err)), nil
			}
			defer release()
			// Resolve explicit proxy flags and environment from the same route.
			ctx, direct, err := s.manifestDirectRoute(ctx, string(m.Limits.Unit))
			if err != nil {
				return actool.Errorf(fmt.Sprintf("select tool route: %v", err)), nil
			}
			proxy := execbox.ProxyURL(ctx, s.m.ProxyAddr())
			if direct {
				proxy = ""
			}
			args, err := m.Resolve(in.Target, effective, proxy)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%v", err)), nil
			}

			timeout := m.Command.TimeoutSeconds
			if timeout <= 0 {
				timeout = 300
			}
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer cancel()
			if tc != nil {
				runCtx = execbox.WithArtifacts(runCtx, execbox.ArtifactCall{Dir: tc.WorkingDir, ToolUseID: tc.ToolUseID})
			}
			output, ref, runErr := runManifestProcess(runCtx, m, args, timeout, proxy, s.m.ProxyCACert())
			// A tool that exits non-zero may still have printed usable rows, so
			// parse whatever arrived before deciding it failed.
			if len(output) == 0 && runErr != nil {
				return actool.Errorf(withArtifactRef(fmt.Sprintf("%s produced no output: %v", in.Tool, runErr), ref)), nil
			}

			result, err := m.Run(string(output))
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%s output could not be parsed: %v", in.Tool, err)), nil
			}

			var b strings.Builder
			fmt.Fprintf(&b, "%s against %s: %d assets, %d facts", in.Tool, in.Target, len(result.Targets), len(result.Facts))
			if result.Skipped > 0 {
				fmt.Fprintf(&b, " (%d emit rules skipped: the manifest may need widening)", result.Skipped)
			}
			b.WriteByte('\n')
			b.WriteString(sandboxBlindNote(m, len(result.Targets), len(result.Facts)))
			for i, t := range result.Targets {
				if i >= 50 {
					fmt.Fprintf(&b, "… and %d more assets\n", len(result.Targets)-50)
					break
				}
				fmt.Fprintf(&b, "  %s %s\n", t.Kind, t.Value)
			}
			for i, f := range result.Facts {
				if i >= 30 {
					fmt.Fprintf(&b, "… and %d more facts\n", len(result.Facts)-30)
					break
				}
				fmt.Fprintf(&b, "  %s %v\n", f.Kind, f.Data)
			}
			if runErr != nil {
				fmt.Fprintf(&b, "\nNote: %s exited non-zero (%v); the rows above were still parsed.\n", in.Tool, runErr)
			}
			return actool.Text(withArtifactRef(b.String(), ref)), nil
		},
	})
}

// sandboxBlindNote distinguishes an empty result from proof of target absence.
func sandboxBlindNote(m *manifest.Manifest, assets, facts int) string {
	if m.Command.Program != "nmap" || assets+facts > 0 {
		return ""
	}
	return "No host answered from this vantage. Nmap requires the scoped VPN direct lane (live tun0, no operator global proxy); without it raw target traffic is blocked. On an available lane use --privileged -Pn as uid 1000 with CAP_NET_RAW, not root; the built-in manifest supplies these flags. Use port_scan or tcp_probe for backend TCP checks when the lane is unavailable.\n"
}

// runManifestProcess starts one manifest tool inside the run's session and
// returns what it wrote to stdout, the same shape the direct spawn it replaced
// produced: stderr is drained and dropped from the parser's input, so a warning
// cannot corrupt it, and a non-zero exit still returns the output for parsing.
// The raw stderr is kept in the process's artifact when the run has one; ref is
// that artifact's pointer, or "" when the run keeps none.
//
// The session comes from the run context, never from a tool argument. There is
// no direct-execution fallback: without an installed client or without a
// session the call refuses with the capability error, so a manifest tool can
// never run in the backend's own network namespace.
//
// The working directory and HOME/TMPDIR are the session's own /tmp, so a tool
// that writes $HOME/.config still works and nothing it writes can reach the
// backend's data root, keys or database socket. proxy and caCert are the run's
// own, so a tool that reads the environment instead of its flag still reaches
// the gateway with this run's credential.
func runManifestProcess(ctx context.Context, m *manifest.Manifest, args []string, timeout int, proxy, caCert string) ([]byte, string, error) {
	client, ok := execbox.Installed()
	if !ok {
		return nil, "", fmt.Errorf("%w: no execution client is installed, so %s was not started", execbox.ErrUnavailable, m.Command.Program)
	}
	sess, err := execbox.RequireSession(ctx)
	if err != nil {
		return nil, "", err
	}
	env := append([]string{"HOME=/tmp", "TMPDIR=/tmp"}, agent.ProxyEnv(proxy, caCert)...)
	// Model-generated inputs (wordlists, request files) live in the trusted
	// tool-call workspace. The supervisor still validates this writable root.
	var writable []string
	if call, ok := execbox.ArtifactsFrom(ctx); ok {
		writable = []string{call.Dir}
	}
	proc, err := client.Run(ctx, sess, execbox.Spec{
		Argv:     append([]string{m.Command.Program}, args...),
		Dir:      "/tmp",
		Env:      env,
		Writable: writable,
	})
	if err != nil {
		return nil, "", err
	}
	p, ok := execbox.ProcessOf(proc)
	if !ok {
		_ = proc.Close()
		return nil, "", fmt.Errorf("%w: the session returned no process control", execbox.ErrUnavailable)
	}
	// Both streams must be read: the client writes each frame to its stream, so
	// leaving stderr unread would stall stdout.
	stderr := p.Stderr()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		if stderr != nil {
			_, _ = io.Copy(io.Discard, stderr)
		}
	}()
	var out bytes.Buffer
	_, readErr := io.Copy(&out, proc)
	code, waitErr := p.Wait()
	<-drained
	ref := execbox.ArtifactPointer(p)
	_ = proc.Close()
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return out.Bytes(), ref, fmt.Errorf("timed out after %ds", timeout)
	case readErr != nil:
		return out.Bytes(), ref, readErr
	case waitErr != nil:
		return out.Bytes(), ref, waitErr
	case code != 0:
		return out.Bytes(), ref, fmt.Errorf("exit status %d", code)
	}
	return out.Bytes(), ref, nil
}

// withArtifactRef appends a process capture pointer to a tool result.
func withArtifactRef(text, ref string) string {
	if ref == "" {
		return text
	}
	return text + "\n" + ref
}

// paramStrings flattens run_tool parameters to the strings a manifest renders.
// A model naturally writes service:true or timing:4, and refusing those cost a
// whole turn; nested values stay rejected because no manifest takes one.
func paramStrings(in map[string]any) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for name, v := range in {
		switch x := v.(type) {
		case nil:
		case string:
			out[name] = x
		case bool:
			out[name] = strconv.FormatBool(x)
		case float64:
			out[name] = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			return nil, fmt.Errorf("parameter %q must be a string, number or boolean", name)
		}
	}
	return out, nil
}

// toolListManifests exposes the catalog so an agent can discover a tool and its
// parameters without the operator pasting a man page into the prompt.
func (s *Server) toolListManifests() actool.CoreTool {
	return wrTool("list_tools",
		"List the reconnaissance and scanning tools available in this environment, with the parameters each accepts and whether its binary is installed. It also states the engagement's rate guidance, so read it before choosing a rate. Pass query to narrow the list by id, name or description when the catalog is long.",
		map[string]any{"type": "object", "properties": map[string]any{
			"query": strParam("optional: only tools whose id, name or description contains this text (case-insensitive)"),
		}},
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(raw, &in)
			query := strings.ToLower(strings.TrimSpace(in.Query))
			var b strings.Builder
			shown := 0
			var body strings.Builder
			set := s.manifests()
			for _, m := range set.All() {
				if query != "" && !strings.Contains(strings.ToLower(m.ID+" "+m.Name+" "+m.Description), query) {
					continue
				}
				shown++
				status := "ready"
				if !binaryPresent(m.Requires) {
					status = "NOT INSTALLED"
				}
				fmt.Fprintf(&body, "- %s [%s, %s] %s\n", m.ID, m.Category, status, m.Description)
				if len(m.Params) > 0 {
					body.WriteString("    params: ")
					first := true
					for name, p := range m.Params {
						if !first {
							body.WriteString(", ")
						}
						first = false
						fmt.Fprintf(&body, "%s(%s)", name, p.Type)
					}
					body.WriteByte('\n')
				}
			}
			if query != "" {
				fmt.Fprintf(&b, "%d of %d tools match %q:\n", shown, set.Len(), in.Query)
			} else {
				fmt.Fprintf(&b, "%d tools:\n", set.Len())
			}
			profile := ""
			if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 && s.m != nil && s.m.PG() != nil {
				var err error
				profile, err = s.m.PG().TaskSpeedProfile(ri.TaskID)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("load task speed profile: %v", err)), nil
				}
			}
			fmt.Fprintf(&b, "\n%s\n\n", limits.GuidanceFor(profile))
			b.WriteString(body.String())
			if shown == 0 {
				b.WriteString("(no tool matches; call list_tools without a query to see the catalog)\n")
			}
			return actool.Text(b.String()), nil
		})
}

// maxInstallOutput bounds what one install returns; the tail is kept because an
// install's failure is at the end of its log.
const maxInstallOutput = 16 << 10

// maxInstallSeconds caps a manifest's own install timeout.
const maxInstallSeconds = 1800

// toolInstallSettingPrefix keys one template's install provenance in the
// settings table. It is an existing key/value column, so a recorded install needs
// no new table and no schema change.
const toolInstallSettingPrefix = "tool_install."

// installVersionMarker prefixes the line the install probe writes, so the binary
// version can be read back out of the same bounded output the operator sees.
const installVersionMarker = "[execbox-version] "

// installStatusCapture keeps the script's own exit status, which the appended
// probe would otherwise replace with its own.
const installStatusCapture = "__install_status=$?\n"

// installVersionProbe reports the version of the binary the template names, read
// inside the same session: the script has just staged it under $PREFIX/bin, which
// is on the session's PATH, so the probe answers about what this install actually
// produced rather than about an earlier publication. $1 is the program, passed as
// an argument rather than interpolated, so a program name can never become shell
// syntax.
const installVersionProbe = "printf '\\n" + installVersionMarker + "%s\\n' \"$(command -v \"$1\" >/dev/null 2>&1 && \"$1\" --version 2>&1 | head -n 1)\"\nexit $__install_status\n"

// toolInstallProvenance is what one install run recorded: which script ran, what
// it came from, what version landed, what was published and whether the tool is
// actually usable.
type toolInstallProvenance struct {
	Template       string `json:"template"`
	ScriptSHA256   string `json:"script_sha256"`
	SourceRevision string `json:"source_revision,omitempty"`
	BinaryVersion  string `json:"binary_version,omitempty"`
	InstalledAt    string `json:"installed_at"`
	Verified       bool   `json:"verified"`
	Verification   string `json:"verification"`
	ExitCode       int    `json:"exit_code"`
	// Published is the artifact the supervisor moved into the persistent toolbox
	// bin directory: its path, digest and size. It is absent when the install
	// staged nothing, and an install that failed published nothing.
	Published *execbox.Published `json:"published,omitempty"`
}

// installResult is one bounded install run: the output, whether it failed, and
// the provenance that was recorded with it.
type installResult struct {
	Output     string                `json:"output"`
	IsError    bool                  `json:"is_error"`
	Available  bool                  `json:"available"`
	Provenance toolInstallProvenance `json:"provenance"`
	// Artifact is the file the bin directory holds after the run, so the sheet
	// can show what was published without waiting for the catalog to reload.
	Artifact *toolArtifact `json:"artifact,omitempty"`
}

// installSession mints the install-purpose session for one approved install.
//
// It is built here, from server-side state only: the purpose is fixed by this
// call site, no tool argument or model output reaches it, and it carries no task
// because an install is operator/curator-initiated rather than task-scoped. That
// is not an authorization: netpolicy judges an install session by the
// public-destination rule, so it can reach the gateway and the public web and
// nothing else - no engagement target, no private or loopback address.
func (s *Server) installSession(ctx context.Context) (netpolicy.Session, error) {
	return s.session(ctx, netpolicy.CallerCurator, 0, conversationIDFromSession(agent.RunInfoFrom(ctx).SessionID), netpolicy.PurposeInstall)
}

// splitInstallVersion removes the probe's line from the output and returns the
// version it reported (empty when the binary was not on PATH in the session).
func splitInstallVersion(text string) (version, rest string) {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(lines[i], installVersionMarker); ok {
			version = strings.TrimSpace(v)
			lines = append(lines[:i], lines[i+1:]...)
			break
		}
	}
	return version, strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// clipInstallOutput keeps the tail of an install log, which is where its failure
// is.
func clipInstallOutput(text string) string {
	if len(text) <= maxInstallOutput {
		return text
	}
	return "[... earlier output clipped]\n" + strings.ToValidUTF8(text[len(text)-maxInstallOutput:], "")
}

// installSpec is the request one install script runs under: the session's own
// /tmp as its working directory, and the install session's proxy environment,
// so a script that downloads reaches the gateway with this session's credential
// instead of the direct network. An install that needs a persistent artifact
// writes it under $PREFIX, which the supervisor publishes.
func (s *Server) installSpec(sess netpolicy.Session, m *manifest.Manifest) execbox.Spec {
	spec := execbox.Spec{
		Argv:        []string{"bash", "-c", m.Install.Script + "\n" + installStatusCapture + installVersionProbe, "install", m.Command.Program},
		Dir:         "/tmp",
		MergeStderr: true,
	}
	if s.m != nil {
		spec.Env = agent.ProxyEnv(netpolicy.ProxyURL(sess, s.m.ProxyAddr()), s.m.ProxyCACert())
	}
	return spec
}

// runManifestInstall runs a template's [install].script inside an install-purpose
// session and records what happened. The operator's Install button and the
// curator's toolbox_install tool both come through here: one path, one boundary,
// no second bash -c.
//
// A successful script has what it staged in $PREFIX published into the
// persistent toolbox bin directory by the supervisor, so the tool survives the
// session and the sandbox. A failed install publishes nothing.
// installArtifacts names the capture of an install. A curator-triggered install
// carries the tool call that caused it, so the artifact can be traced back to
// that call; an install the operator started from the Toolbox has no tool call,
// and is recorded as an operator action rather than with a fabricated id.
func installArtifacts(dir string, ctx context.Context) execbox.ArtifactCall {
	if id, ok := actool.ExecIdentityFrom(ctx); ok && id.ToolUseID != "" {
		return execbox.ArtifactCall{Dir: dir, ToolUseID: id.ToolUseID, Origin: execbox.OriginTool}
	}
	return execbox.ArtifactCall{Dir: dir, Origin: execbox.OriginOperator}
}

func (s *Server) runManifestInstall(ctx context.Context, m *manifest.Manifest, sourceRevision string) installResult {
	out := installResult{Provenance: toolInstallProvenance{
		Template:       m.ID,
		ScriptSHA256:   fmt.Sprintf("%x", sha256.Sum256([]byte(m.Install.Script))),
		SourceRevision: strings.TrimSpace(sourceRevision),
		InstalledAt:    time.Now().UTC().Format(time.RFC3339),
	}}
	client, ok := execbox.Installed()
	if !ok {
		out.IsError = true
		out.Provenance.Verification = "isolated execution is unavailable, so the install script was not run"
		return s.recordInstall(ctx, out)
	}
	sess, err := s.installSession(ctx)
	if err != nil {
		out.IsError = true
		out.Provenance.Verification = "no install session could be issued: " + err.Error()
		return s.recordInstall(ctx, out)
	}
	// Parse already defaults a script's timeout, so only the cap applies here.
	timeout := time.Duration(min(m.Install.TimeoutSeconds, maxInstallSeconds)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// An install the operator starts from the Toolbox has no tool call behind it,
	// so its capture is recorded as an operator action: no fabricated tool_use
	// id. A curator-triggered install does have one, and the capture carries it
	// so the call that caused the install can be found from its artifact.
	if s.m != nil {
		runCtx = execbox.WithArtifacts(runCtx, installArtifacts(s.m.dir, runCtx))
	}
	run, err := client.RunOnce(runCtx, sess, s.installSpec(sess, m))
	version, text := splitInstallVersion(strings.ToValidUTF8(string(run.Output), ""))
	out.Output = withArtifactRef(clipInstallOutput(text), run.Artifact)
	out.Provenance.BinaryVersion = version
	out.Provenance.ExitCode = run.ExitCode
	requires := strings.Join(m.Requires, ", ")
	switch {
	case errors.Is(err, execbox.ErrUnavailable):
		out.IsError = true
		out.Provenance.Verification = "the isolated boundary refused the install: " + err.Error()
	case runCtx.Err() == context.DeadlineExceeded:
		out.IsError = true
		out.Provenance.Verification = fmt.Sprintf("the install ran past its %s timeout and was killed", timeout)
	case err != nil:
		out.IsError = true
		out.Provenance.Verification = "the install did not finish: " + err.Error()
	case run.ExitCode != 0:
		out.IsError = true
		out.Provenance.Verification = fmt.Sprintf("the install script exited %d", run.ExitCode)
	default:
		// A template that names an absolute program path installs outside the
		// staging prefix, so there is nothing to publish.
		if !strings.ContainsRune(m.Command.Program, '/') {
			if pub, pubErr := execbox.PublishArtifact(client, ctx, sess, m.Command.Program); pubErr != nil {
				if !errors.Is(pubErr, execbox.ErrNotStaged) {
					out.IsError = true
					out.Provenance.Verification = "the install staged " + m.Command.Program + " but the publish was refused: " + pubErr.Error()
					return s.recordInstall(ctx, out)
				}
			} else {
				out.Provenance.Published = &pub
			}
		}
		out.Available = binaryPresent(m.Requires)
		if out.Available {
			out.Provenance.Verified = true
			out.Provenance.Verification = "the install script exited 0 and " + requires + " is on PATH"
			if pub := out.Provenance.Published; pub != nil {
				out.Provenance.Verification = fmt.Sprintf(
					"the install script exited 0; %s was published to %s (sha256 %s, %d bytes) and is on PATH in every session - /state survives sandbox recreation, so it stays installed",
					pub.Name, pub.Path, pub.SHA256, pub.Size)
			}
		} else {
			out.Provenance.Verification = "the install script exited 0 but " + requires +
				" is not on PATH: nothing was staged at $PREFIX/bin/" + m.Command.Program + ", so there was nothing to publish"
		}
	}
	return s.recordInstall(ctx, out)
}

// recordInstall stores the run's provenance and returns it, so the caller reports
// exactly what was kept. A storage failure is reported rather than hidden: an
// install whose provenance could not be kept is not a verified install.
func (s *Server) recordInstall(ctx context.Context, out installResult) installResult {
	if s.m == nil || s.m.pg == nil || s.m.pg.DB == nil {
		return out
	}
	b, err := json.Marshal(out.Provenance)
	if err != nil {
		return out
	}
	if err := s.m.pg.SetSetting(toolInstallSettingPrefix+out.Provenance.Template, string(b)); err != nil {
		log.Printf("[toolbox] install provenance for %s not stored: %v", out.Provenance.Template, err)
		out.Provenance.Verified = false
		out.Provenance.Verification += " (the provenance record could not be stored: " + err.Error() + ")"
	}
	return out
}

// installToolManifest handles POST /api/tool-manifests/{id}/install: it runs the
// manifest's own install script through the isolated install path, publishes what
// it staged into the persistent toolbox, and reports the log, the provenance and
// whether the required binaries are now on PATH.
func (s *Server) installToolManifest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m := s.manifests().Get(id)
	if m == nil {
		writeErr(w, 404, fmt.Sprintf("unknown tool %q", id))
		return
	}
	if strings.TrimSpace(m.Install.Script) == "" {
		writeErr(w, 400, fmt.Sprintf("%s has no install script", id))
		return
	}
	out := s.runManifestInstall(r.Context(), m, "")
	// Read the bin directory after the run: it is the authority on what is
	// installed, and a re-install that failed still leaves the earlier binary
	// on PATH, which the operator must see.
	out.Artifact = publishedArtifact(m.Command.Program)
	writeJSON(w, 200, out)
}

// saveToolManifest handles POST /api/tool-manifests.
func (s *Server) saveToolManifest(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	var req struct {
		TOML string `json:"toml"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "invalid JSON body")
		return
	}
	id, err := s.saveManifest(r.Context(), req.TOML)
	var invalid manifestInvalidError
	switch {
	case errors.As(err, &invalid):
		writeErr(w, 400, err.Error())
	case err != nil:
		writeErr(w, 500, err.Error())
	default:
		writeJSON(w, 200, map[string]any{"id": id})
	}
}

// deleteToolManifest handles DELETE /api/tool-manifests/{id}. Only stored rows
// can be deleted: a pure built-in is part of the binary, and deleting a
// modified one simply brings the shipped version back.
func (s *Server) deleteToolManifest(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id := r.PathValue("id")
	deleted, err := pg.DeleteToolManifest(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !deleted {
		writeErr(w, 404, fmt.Sprintf("no stored template %q (a built-in cannot be deleted)", id))
		return
	}
	if err := s.reloadManifests(r.Context()); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}
