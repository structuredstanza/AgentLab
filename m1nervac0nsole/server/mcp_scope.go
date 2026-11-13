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

// browserToolPrefix marks every tool of the browser MCP server.
const browserToolPrefix = "mcp__browser__"

// scopeGuardTool wraps a browser tool with the task boundary: a navigation's url
// argument is judged before the page loads, and the page every call reports is
// judged after it, so a server-side redirect or a click that navigates cannot
// land the run off-scope. Other MCP servers' tools are returned unchanged.
func scopeGuardTool(assets *db.AssetStore, t actool.CoreTool) actool.CoreTool {
	if !strings.HasPrefix(t.Name(), browserToolPrefix) {
		return t
	}
	return &scopeGuard{CoreTool: t, assets: assets}
}

type scopeGuard struct {
	actool.CoreTool
	assets *db.AssetStore
}

// Call judges the boundary twice: the navigation's url before the MCP server is
// asked to open it, and the page the call reports afterwards, because a redirect
// or a click can navigate after the argument was judged.
//
// A run with no task (the main agent, chat) has no boundary to enforce, so it
// passes through. A task whose boundary cannot be read is refused rather than
// guessed: this is a boundary, and "I could not check" is not "allowed" - the
// same rule db.TaskScopeChecker applies to an unreadable scope. A task with no
// exclusion rows is allowed, matching guard.checkScope, where only an explicit
// exclusion blocks: scope rows accumulate as the hunt finds assets, so treating
// "no rule matches" as out would refuse the first page of every fresh task.
//
// A page may still *contain* links to off-scope hosts; following one is a
// navigation and is judged. The recording proxy sees every request either way.
func (g *scopeGuard) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return g.CoreTool.Call(ctx, in, tc)
	}
	checker := db.NewTaskScopeChecker(g.assets, ri.TaskID)
	if browserNavTools[g.CoreTool.Name()] {
		var args struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(in, &args); err != nil {
			return actool.Errorf("Error: browser navigation refused: the call arguments are not valid JSON: " + err.Error()), nil
		}
		host, refusal := browserURLHost(args.URL)
		if refusal != "" {
			return actool.Errorf("Error: browser navigation refused: " + refusal), nil
		}
		if refusal := scopeRefusal(checker, host); refusal != "" {
			return actool.Errorf("Error: browser navigation refused: " + refusal), nil
		}
	}
	res, err := g.CoreTool.Call(ctx, in, tc)
	if err != nil || res.IsError {
		return res, err
	}
	if landed := pageURLFromResult(res); landed != "" {
		host, refusal := browserURLHost(landed)
		if refusal == "" {
			refusal = scopeRefusal(checker, host)
		}
		if refusal != "" {
			return actool.Errorf(fmt.Sprintf("Error: the browser landed on an out-of-scope page: %s. Stop interacting with it, close the page, and note the boundary in your intent summary.", refusal)), nil
		}
	}
	return res, err
}

// browserURLHost validates the shape of a URL a browser call is about to load or
// has loaded, and returns its host. A refusal is a message for the model.
func browserURLHost(rawURL string) (host, refusal string) {
	raw := strings.TrimSpace(rawURL)
	// Chromium treats a backslash as a path separator in special URLs, which is a
	// host-parser differential. Go rejects a backslash in the authority today,
	// but refuse the shape outright rather than depend on that.
	if strings.Contains(raw, `\`) {
		return "", fmt.Sprintf("backslashes are not allowed in a URL, got %q", raw)
	}
	u, err := url.Parse(raw)
	if err != nil || (strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https") || u.Hostname() == "" {
		return "", fmt.Sprintf("only absolute http(s) URLs are allowed, got %q", raw)
	}
	host = u.Hostname()
	// Chromium maps Unicode dots (U+3002, U+FF0E, U+FF61) and fullwidth letters
	// in a host to ASCII (UTS46/IDNA), so a host spelled with U+3002 reaches
	// evil.example while Go reports the literal Unicode host and an exclusion on
	// evil.example would miss it. Require ASCII; an IDN target can be named in
	// punycode, which both parsers canonicalise to the same host.
	for i := range len(host) {
		if host[i] >= 0x80 {
			return "", fmt.Sprintf("non-ASCII hostname %q; use its punycode form", host)
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
		return "", fmt.Sprintf("%q is not a canonical IPv4 address; write it as four decimal octets", host)
	}
	return host, ""
}

// scopeRefusal judges a host against the task boundary. A boundary that cannot
// be read is a refusal, not a pass.
func scopeRefusal(checker *db.TaskScopeChecker, host string) string {
	if checker == nil {
		return "no task scope checker is available, so the boundary cannot be checked"
	}
	// Judge the parsed hostname, not the raw URL: scope.ParseAsset does not strip
	// userinfo, so `http://user:pass@excluded.example/` would be read as host
	// "user" and an excluded host would pass. The checker only matches hosts,
	// domains and networks, so the hostname is all it needs.
	if out, reason := checker.Judge(host); out {
		return fmt.Sprintf("%s is out of scope for this task (%s). Do not retry it", host, reason)
	}
	return ""
}

// pageURLFromResult reads the page a browser call reports. Playwright prints it
// as a "- Page URL: <url>" line in the tool's text; a result without that line
// makes no claim, so nothing is judged.
func pageURLFromResult(res actool.Result) string {
	for _, b := range res.Content {
		for _, line := range strings.Split(b.Text, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "- Page URL:"); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
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
