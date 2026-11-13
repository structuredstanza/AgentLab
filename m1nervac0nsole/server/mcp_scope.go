package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	actool "github.com/structuredstanza/norma/tool"
)

// browserNavTools are the MCP tool names whose `url` argument crosses the task
// boundary. Playwright names its tools `browser_navigate`/`browser_open`, so the
// client's `mcp__<server>__<tool>` prefix yields the doubled form; the bare form
// is accepted too, for a server that names its tools `navigate`/`open`.
var browserNavTools = map[string]bool{
	"mcp__browser__navigate":         true,
	"mcp__browser__open":             true,
	"mcp__browser__browser_navigate": true,
	"mcp__browser__browser_open":     true,
}

// scopeGuardTool wraps a browser navigation tool with the task boundary.
//
// MCP calls never pass through guard/: the guard's text scan is wired to the
// Bash-oriented tool pipeline, and a browser navigation is a different shape (a
// URL argument, not a command line). Judging it here is the only place the
// boundary sees it before the page loads. Other tools are returned unchanged.
func scopeGuardTool(assets *db.AssetStore, t actool.CoreTool) actool.CoreTool {
	if !browserNavTools[t.Name()] {
		return t
	}
	return &scopeGuard{CoreTool: t, assets: assets}
}

type scopeGuard struct {
	actool.CoreTool
	assets *db.AssetStore
}

// Call judges the navigation's url against the task's exclusions before the MCP
// server is asked to open it.
//
// A run with no task (the main agent, chat) has no boundary to enforce, so it
// passes through. A task whose boundary cannot be read is refused rather than
// guessed: this is a boundary, and "I could not check" is not "allowed" - the
// same rule db.TaskScopeChecker applies to an unreadable scope. A task with no
// exclusion rows is allowed, matching guard.checkScope, where only an explicit
// exclusion blocks: scope rows accumulate as the hunt finds assets, so treating
// "no rule matches" as out would refuse the first page of every fresh task.
//
// shortcut: the URL is judged before the call, so a server-side redirect can
// still land off-scope; the recording proxy sees it, but it is not refused here.
func (g *scopeGuard) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return g.CoreTool.Call(ctx, in, tc)
	}
	var args struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(in, &args); err != nil {
		return actool.Errorf("Error: browser navigation refused: the call arguments are not valid JSON: " + err.Error()), nil
	}
	raw := strings.TrimSpace(args.URL)
	// Chromium treats a backslash as a path separator in special URLs, which is a
	// host-parser differential. Go rejects a backslash in the authority today,
	// but refuse the shape outright rather than depend on that.
	if strings.Contains(raw, `\`) {
		return actool.Errorf(fmt.Sprintf("Error: browser navigation refused: backslashes are not allowed in a URL, got %q", raw)), nil
	}
	u, err := url.Parse(raw)
	if err != nil || (strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https") || u.Hostname() == "" {
		return actool.Errorf(fmt.Sprintf("Error: browser navigation refused: only absolute http(s) URLs are allowed, got %q", raw)), nil
	}
	host := u.Hostname()
	// Chromium maps Unicode dots (U+3002, U+FF0E, U+FF61) and fullwidth letters
	// in a host to ASCII (UTS46/IDNA), so a host spelled with U+3002 reaches
	// evil.example while Go reports the literal Unicode host and an exclusion on
	// evil.example would miss it. Require ASCII; an IDN target can be named in
	// punycode, which both parsers canonicalise to the same host.
	for i := range len(host) {
		if host[i] >= 0x80 {
			return actool.Errorf(fmt.Sprintf("Error: browser navigation refused: non-ASCII hostname %q; use its punycode form", host)), nil
		}
	}
	// WHATWG reads IPv4 in decimal, octal and hex forms, so `2130706433`,
	// `127.1` and `0x7f.0.0.1` all reach 127.0.0.1 while Go reports the literal
	// string and a CIDR exclusion would miss it. Accept only the canonical
	// dotted-quad spelling; any other host ending in an IPv4 number is refused.
	trimmed := strings.TrimRight(host, ".")
	last := trimmed
	if i := strings.LastIndex(trimmed, "."); i >= 0 {
		last = trimmed[i+1:]
	}
	if isIPv4Number(last) && net.ParseIP(trimmed) == nil {
		return actool.Errorf(fmt.Sprintf("Error: browser navigation refused: %q is not a canonical IPv4 address; write it as four decimal octets", host)), nil
	}
	checker := db.NewTaskScopeChecker(g.assets, ri.TaskID)
	if checker == nil {
		return actool.Errorf("Error: browser navigation refused: no task scope checker is available, so the boundary cannot be checked"), nil
	}
	// Judge the parsed hostname, not the raw URL: scope.ParseAsset does not strip
	// userinfo, so `http://user:pass@excluded.example/` would be read as host
	// "user" and an excluded host would pass. The checker only matches hosts,
	// domains and networks, so the hostname is all it needs.
	if out, reason := checker.Judge(host); out {
		return actool.Errorf(fmt.Sprintf("Error: browser navigation refused: %s is out of scope for this task (%s). Do not retry it; note the boundary in your intent summary.", host, reason)), nil
	}
	return g.CoreTool.Call(ctx, in, tc)
}

// isIPv4Number reports whether a host label is a number under the WHATWG IPv4
// parser: decimal digits, 0x-prefixed hex, or 0-prefixed octal.
func isIPv4Number(label string) bool {
	if label == "" {
		return false
	}
	if len(label) > 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') {
		for i := 2; i < len(label); i++ {
			c := label[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	}
	for i := range len(label) {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}
