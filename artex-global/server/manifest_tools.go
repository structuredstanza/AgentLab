package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/Autumn-27/artex/limits"
	"github.com/Autumn-27/artex/manifest"
	actool "github.com/Autumn-27/norma/tool"
)

// manifestTools is the shipped tool manifest set, loaded once.
var manifestTools = manifest.LoadBuiltin()

// engagementLimits caps throughput for manifest-backed tools.
//
// The proxy caps HTTP requests, but it cannot see a raw packet scan, and a
// manifest default is only a suggestion: the caller can pass any rate it likes.
// This is where a declared rate becomes a binding one.
var engagementLimits = limits.New(limits.DefaultLabPolicy())

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
		"Run a reconnaissance or scanning tool declared by a manifest, and return its parsed records, the assets it found and the facts it recorded. Call list_tools first to see the parameters each tool accepts. Prefer this over Bash for any tool that appears in the list: the manifest pins the flags, parses the output into assets, and refuses an out-of-scope target.",
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
					"description": "Tool parameters, keyed by the names list_tools reports",
				},
			},
			"required": []string{"tool", "target"},
		},
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				Tool   string            `json:"tool"`
				Target string            `json:"target"`
				Params map[string]string `json:"params"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(fmt.Sprintf("bad input: %v", err)), nil
			}
			m := manifestTools.Get(in.Tool)
			if m == nil {
				return actool.Errorf(fmt.Sprintf("unknown tool %q; call list_tools for the manifest ids", in.Tool)), nil
			}
			if !binaryPresent(m.Requires) {
				return actool.Errorf(fmt.Sprintf("%s is declared but not installed in this environment (needs %s)",
					in.Tool, strings.Join(m.Requires, ", "))), nil
			}
			effective, err := m.Effective(in.Params)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			// Clamp before resolving, so the argv carries the ceiling rather than
			// the number the caller asked for.
			effective, clampNote := engagementLimits.Clamp(m, effective)
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
			if clampNote != "" {
				fmt.Fprintf(&b, "\nNote: %s, to stay inside the engagement's rate policy.", clampNote)
			}
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

// toolListManifests exposes the catalog so an agent can discover a tool and its
// parameters without the operator pasting a man page into the prompt.
func (s *Server) toolListManifests() actool.CoreTool {
	return wrTool("list_tools",
		"List the reconnaissance and scanning tools available in this environment, with the parameters each accepts and whether its binary is installed.",
		map[string]any{"type": "object", "properties": map[string]any{}},
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			var b strings.Builder
			fmt.Fprintf(&b, "%d tools:\n", manifestTools.Len())
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
