package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	pgdb "github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/limits"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	actool "github.com/structuredstanza/norma/tool"
)

// manifestTools is the shipped tool manifest set, loaded once.
var manifestTools = manifest.LoadBuiltin()

// engagementLimits caps throughput for manifest-backed tools.
//
// The proxy caps HTTP requests, but it cannot see a raw packet scan, and a
// manifest default is only a suggestion: the caller can pass any rate it likes.
// This is where a declared rate becomes a binding one.
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
	if v, err := strconv.Atoi(os.Getenv("M1NERVAC0NSOLE_MAX_REQUESTS_PER_MINUTE")); err == nil && v > 0 {
		p.MaxRequestsPerMinute = v
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
}

func (s *Server) listToolManifests(w http.ResponseWriter, r *http.Request) {
	out := make([]toolManifest, 0, manifestTools.Len())
	for _, m := range manifestTools.All() {
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
		})
	}
	writeJSON(w, 200, map[string]any{"tools": out})
}

func binaryPresent(bins []string) bool {
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			return false
		}
	}
	return true
}

// toolRunManifest executes one manifest-backed tool and returns the parsed
// records plus the assets and facts its emit rules produced.
//
// The tool is invoked without a shell, so a parameter containing a space stays
// one argument and no operator input can be read as a shell metacharacter.
func (s *Server) toolRunManifest() actool.CoreTool {
	return wrTool("run_tool",
		"Run a reconnaissance or scanning tool declared by a manifest, and return its parsed records, the assets it found and the facts it recorded. Call list_tools first to see the parameters each tool accepts. Prefer this over Bash for any tool that appears in the list: the manifest pins the flags, parses the output into assets, and refuses an out-of-scope target. "+engagementLimits.Guidance(),
		map[string]any{
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
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
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
			m := manifestTools.Get(in.Tool)
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
			// No clamping: the proxy enforces the hard ceiling, and pinning every
			// tool to one request a second made a real scan take hours. The
			// description asks for a sensible rate instead.
			release, err := engagementLimits.Acquire(ctx, in.Target, m, effective)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%s not started: %v", in.Tool, err)), nil
			}
			defer release()
			args, err := m.Resolve(in.Target, effective)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%v", err)), nil
			}

			timeout := m.Command.TimeoutSeconds
			if timeout <= 0 {
				timeout = 300
			}
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer cancel()
			cmd := exec.CommandContext(runCtx, m.Command.Program, args...)
			output, runErr := cmd.Output()
			// A tool that exits non-zero may still have printed usable rows, so
			// parse whatever arrived before deciding it failed.
			if len(output) == 0 && runErr != nil {
				return actool.Errorf(fmt.Sprintf("%s produced no output: %v", in.Tool, runErr)), nil
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
			return actool.Text(b.String()), nil
		})
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
		"List the reconnaissance and scanning tools available in this environment, with the parameters each accepts and whether its binary is installed. It also states the engagement's rate guidance, so read it before choosing a rate.",
		map[string]any{"type": "object", "properties": map[string]any{}},
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			var b strings.Builder
			fmt.Fprintf(&b, "%d tools:\n", manifestTools.Len())
			if g := engagementLimits.Guidance(); g != "" {
				fmt.Fprintf(&b, "\n%s\n\n", g)
			}
			for _, m := range manifestTools.All() {
				status := "ready"
				if !binaryPresent(m.Requires) {
					status = "NOT INSTALLED"
				}
				fmt.Fprintf(&b, "- %s [%s, %s] %s\n", m.ID, m.Category, status, m.Description)
				if len(m.Params) > 0 {
					b.WriteString("    params: ")
					first := true
					for name, p := range m.Params {
						if !first {
							b.WriteString(", ")
						}
						first = false
						fmt.Fprintf(&b, "%s(%s)", name, p.Type)
					}
					b.WriteByte('\n')
				}
			}
			return actool.Text(b.String()), nil
		})
}
