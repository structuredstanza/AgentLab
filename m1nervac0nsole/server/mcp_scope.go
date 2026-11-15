package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	actool "github.com/structuredstanza/norma/tool"
)

// nativeBrowserPrefix marks the tools of the built-in driver (browser/), the
// testing browser. They take the task boundary checks below.
const nativeBrowserPrefix = "browser_"

// browserNavTools are the native tool names whose `url` argument crosses the
// task boundary.
var browserNavTools = map[string]bool{
	"browser_navigate": true,
	"browser_open":     true,
}

// scopeGuardTool wraps a native browser tool with the task boundary: a
// navigation's url argument is judged before the page loads, and the page every
// call reports is judged after it, so a server-side redirect or a click that
// navigates cannot land the run off-scope. Other tools are returned unchanged.
func scopeGuardTool(assets *db.AssetStore, t actool.CoreTool) actool.CoreTool {
	if !strings.HasPrefix(t.Name(), nativeBrowserPrefix) {
		return t
	}
	return &scopeGuard{CoreTool: t, assets: assets}
}

type scopeGuard struct {
	actool.CoreTool
	assets *db.AssetStore
}

// Call judges the boundary twice: the navigation's url before the browser is
// asked to open it, and the page the call reports afterwards, because a redirect
// or a click can navigate after the argument was judged.
//
// A run with no task (the main agent, chat) has no boundary to enforce here: the
// tool itself refuses to launch a browser without a task, and points at the
// research browser instead. A task whose boundary cannot be read is refused
// rather than guessed: this is a boundary, and "I could not check" is not
// "allowed" - the same rule db.TaskScopeChecker applies to an unreadable scope.
// A task with no exclusion rows is allowed, matching guard.checkScope, where
// only an explicit exclusion blocks: scope rows accumulate as the hunt finds
// assets, so treating "no rule matches" as out would refuse the first page of
// every fresh task.
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

// researchMCPServer is the seeded research browser. It is the only browser a run
// without a task may drive, and it reads rather than interacts.
const researchMCPServer = "obscura"

// obscuraToolPrefix marks the research browser's MCP tools.
const obscuraToolPrefix = "mcp__obscura__"

// obscuraReadTools is the research browser's whole surface: navigate, read and
// extract. Everything else the server offers is left out on purpose - evaluate,
// wait_for_function, cookies and storage, fill, click, tab_new - because a
// lookup needs to read a page, not drive a session, and every tool left out is
// one a hostile page cannot reach through a prompt injection.
var obscuraReadTools = map[string]bool{
	"browser_navigate":      true,
	"browser_markdown":      true,
	"browser_links":         true,
	"browser_extract":       true,
	"browser_snapshot":      true,
	"browser_search":        true,
	"browser_back":          true,
	"browser_forward":       true,
	"browser_reload":        true,
	"browser_wait_for_text": true,
	"browser_close":         true,
}

// researchToolAllowed reports whether an MCP tool may be exposed at all. Only the
// research browser is filtered; every other server keeps its whole surface.
func researchToolAllowed(server, tool string) bool {
	if server != researchMCPServer {
		return true
	}
	name, ok := strings.CutPrefix(tool, obscuraToolPrefix)
	return ok && obscuraReadTools[name]
}

// researchProxyFor returns the gateway proxy URL a research MCP child must use,
// with the session credential the backend issued for this run, the recorder's
// CA the child must trust, and the revoke that ends the credential. The server
// sets it at startup; nil means no gateway runs, and the child gets neither a
// proxy argument nor a CA.
var researchProxyFor func(ctx context.Context) (proxyURL, caCert string, revoke func(), err error)

// researchProxy returns the gateway proxy URL for the research child. The gateway
// accepts no anonymous request, so the URL carries the credential IssueSession
// minted for this run's purpose, task and conversation - none of which a tool
// argument can reach. An empty URL means no gateway runs: the child gets no proxy
// and the session's packet boundary is the only control left.
//
// The CA comes with it because the recorder re-signs every certificate it
// forwards; a child that does not trust it cannot read a single HTTPS page.
func (s *Server) researchProxy(ctx context.Context) (string, string, func(), error) {
	if s.m.Traffic() == nil || !s.m.TrafficEnabled() {
		return "", "", nil, nil
	}
	addr := s.m.Traffic().ProxyAddr()
	if addr == "" {
		return "", "", nil, nil
	}
	ri := agent.RunInfoFrom(ctx)
	caller := netpolicy.CallerChat
	if ri.TaskID > 0 {
		caller = netpolicy.CallerAgent
	}
	sess, err := s.m.IssueSession(ctx, caller, ri.TaskID, conversationIDFromSession(ri.SessionID), netpolicy.PurposeResearch)
	if err != nil {
		return "", "", nil, err
	}
	proxy := netpolicy.ProxyURL(sess, addr)
	if proxy == "" {
		s.m.RevokeSession(sess.Credential)
		return "", "", nil, errors.New("research proxy: the session carries no credential")
	}
	return proxy, s.m.ProxyCACert(), func() { s.m.RevokeSession(sess.Credential) }, nil
}

// researchGuardTool wraps the research browser's tools with the research policy:
// a destination that is an engagement target or a private/internal address is
// refused before obscura loads it, and a navigation that lands on one is refused
// after. Other MCP servers' tools are returned unchanged.
//
// It is deliberately not the task scope guard: research has no task, and its
// boundary is "the public web minus every task's authorized targets", which is
// what netpolicy.PurposeResearch decides.
func researchGuardTool(auth *netpolicy.Store, t actool.CoreTool) actool.CoreTool {
	if !strings.HasPrefix(t.Name(), obscuraToolPrefix) {
		return t
	}
	return &researchGuard{CoreTool: t, auth: auth}
}

type researchGuard struct {
	actool.CoreTool
	auth *netpolicy.Store
}

func (g *researchGuard) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	sess := researchSession(ctx)
	var args struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(in, &args)
	if refusal := g.judge(ctx, sess, args.URL); refusal != "" {
		return actool.Errorf("Error: research refused: " + refusal), nil
	}
	res, err := g.CoreTool.Call(ctx, in, tc)
	if err != nil || res.IsError {
		return res, err
	}
	if landed := obscuraPageURL(res); landed != "" {
		if refusal := g.judge(ctx, sess, landed); refusal != "" {
			return actool.Errorf(fmt.Sprintf("Error: the research browser landed on %s, which it may not read: %s. Stop here and say what the page redirected to.", landed, refusal)), nil
		}
	}
	return res, err
}

// judge asks the policy authorizer about one destination. A destination the
// authorizer cannot judge is refused: "I could not check" is not "allowed".
func (g *researchGuard) judge(ctx context.Context, sess netpolicy.Session, raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	d, refusal := researchDestination(raw)
	if refusal != "" {
		return refusal
	}
	if dec := g.auth.Authorize(ctx, sess, d); !dec.Allow {
		return fmt.Sprintf("%s is not reachable for research (%s). A target system is tested with the native browser inside a task; a public page is looked up elsewhere", d.Host, dec.Reason)
	}
	return ""
}

// researchSession is the backend-issued identity a research tool call runs under.
// Research carries no task: its policy is the public web minus every live task's
// authorized targets, so a task id would add nothing, and an archived task must
// not break a lookup. Revision 0 means "whatever the stored revision is now"; the
// authorizer re-reads it on every call.
func researchSession(ctx context.Context) netpolicy.Session {
	ri := agent.RunInfoFrom(ctx)
	return netpolicy.Session{
		ID:             "research:" + strconv.FormatInt(ri.TaskID, 10) + ":" + ri.SessionID,
		ConversationID: conversationIDFromSession(ri.SessionID),
		Purpose:        netpolicy.PurposeResearch,
	}
}

// researchDestination turns a URL a research tool is about to load into the
// destination the authorizer judges.
func researchDestination(raw string) (netpolicy.Destination, string) {
	host, refusal := browserURLHost(raw)
	if refusal != "" {
		return netpolicy.Destination{}, refusal
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return netpolicy.Destination{}, fmt.Sprintf("only absolute http(s) URLs are allowed, got %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	port := 443
	if scheme == "http" {
		port = 80
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return netpolicy.Destination{}, fmt.Sprintf("the port in %q is not a number", raw)
		}
		port = n
	}
	return netpolicy.Destination{Scheme: scheme, Host: host, Port: port, Protocol: "http"}, ""
}

// obscuraPageURL reads the page a research call reports, so a redirect is judged
// on where it actually landed. Obscura answers a navigation with "Navigated to
// <url> - <title>", "Back to <url>", "Forward to <url>" or "Reloaded <url>", and
// its snapshot starts with "URL: <url>". A result without one of those lines
// makes no claim, so nothing is judged.
func obscuraPageURL(res actool.Result) string {
	for _, b := range res.Content {
		for _, line := range strings.Split(b.Text, "\n") {
			line = strings.TrimSpace(line)
			for _, prefix := range []string{"Navigated to ", "Back to ", "Forward to ", "Reloaded ", "URL: "} {
				v, ok := strings.CutPrefix(line, prefix)
				if !ok {
					continue
				}
				if prefix == "Navigated to " {
					// "Navigated to <url> \u2014 \"<title>\"": the title is not
					// part of the URL.
					v, _, _ = strings.Cut(v, " \u2014 ")
				}
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// conversationIDFromSession reads the conversation id out of a chat run's session
// key ("conv-<id>"). A task run carries no session key, so it yields 0.
func conversationIDFromSession(session string) int64 {
	id, err := strconv.ParseInt(strings.TrimPrefix(session, "conv-"), 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
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

// pageURLFromResult reads the page a browser call reports. The native tools print
// it as a "- Page URL: <url>" line in the tool's text; a result without that line
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
