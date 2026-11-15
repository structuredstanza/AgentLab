package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/mcphttp"
	"github.com/structuredstanza/norma/mcp"
	actool "github.com/structuredstanza/norma/tool"
)

// envList renders an MCP server's configured environment as KEY=VALUE entries
// for the isolated session, in a stable order.
func envList(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// mcpClient is the shared surface of a connected MCP server (stdio, Streamable HTTP,
// or legacy SSE),
// so tools/list and cleanup are handled uniformly regardless of transport.
type mcpClient interface {
	Tools(context.Context) ([]actool.CoreTool, error)
	Close() error
}

// These transport configuration errors are shown by MCP discovery endpoints.
// Keep protocol names and URLs unchanged.
const (
	errMCPStdioNoCommand      = "The stdio transport has no command"
	errMCPHTTPNoURL           = "The http transport has no URL"
	errMCPSSENoURL            = "The sse transport has no URL"
	errMCPUnknownTransportFmt = "Unknown transport: %q"
)

// connectMCP dials one MCP server per its transport. Callers must Close the client.
func connectMCP(ctx context.Context, m *db.MCPServer) (mcpClient, error) {
	switch m.Transport {
	case "stdio":
		if m.Command == "" {
			return nil, errors.New(errMCPStdioNoCommand)
		}
		// The MCP server is untrusted code. It is started by the supervisor
		// inside a session, through the bridge, so it cannot reach the
		// controller's network, files or credentials. A caller with no session
		// gets the capability error rather than an unisolated child.
		sess, err := execbox.RequireSession(ctx)
		if err != nil {
			return nil, err
		}
		argv := append([]string{m.Command}, jsonStrSlice(m.Args)...)
		command, args, env, err := execbox.BridgeCommand(sess, argv, envList(jsonStrMap(m.Env)))
		if err != nil {
			return nil, err
		}
		return mcp.NewStdioClient(ctx, m.Name, command, env, args...)
	case "http":
		if m.URL == "" {
			return nil, errors.New(errMCPHTTPNoURL)
		}
		// env map doubles as HTTP headers (e.g. Authorization).
		return mcphttp.New(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure, m.TimeoutSeconds)
	case "sse":
		if m.URL == "" {
			return nil, errors.New(errMCPSSENoURL)
		}
		return mcphttp.NewSSE(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
	default:
		return nil, fmt.Errorf(errMCPUnknownTransportFmt, m.Transport)
	}
}

// discoverAndCacheMCP connects to one MCP, lists its tools, and persists the tool
// names to mcp_tools_cache so the UI shows them without a live connection.
func (s *Server) discoverAndCacheMCP(ctx context.Context, m *db.MCPServer) error {
	// Discovery is a backend lookup with no task, so it runs as unbound research.
	// A stdio server started without a session refuses with the capability error
	// instead of running unisolated.
	ctx = s.discoverySessionContext(ctx)
	cl, err := connectMCP(ctx, m)
	if err != nil {
		_ = s.m.pg.UpdateMCPHealth(m.ID, false, err.Error())
		return err
	}
	defer cl.Close()
	ts, err := cl.Tools(ctx)
	if err != nil {
		_ = s.m.pg.UpdateMCPHealth(m.ID, false, err.Error())
		return err
	}
	_ = s.m.pg.UpdateMCPHealth(m.ID, true, "")
	tools := make([]db.MCPTool, 0, len(ts))
	for _, t := range ts {
		tools = append(tools, db.MCPTool{Name: t.Name(), Description: t.Description()})
	}
	if err := s.m.pg.SaveMCPTools(m.ID, tools); err != nil {
		return err
	}
	log.Printf("[mcp] from %s, discovered and cached %d tool(s)", m.Name, len(tools))
	return nil
}

// discoverEmptyMCPsOnStartup fills the tool cache for any enabled MCP that has none
// yet (notably the seeded browser MCP on first run). Runs sequentially in one
// goroutine so we never spawn many stdio servers (npx) at once, and never blocks
// startup. Best-effort: a failure leaves the cache empty to retry next start.
func (s *Server) discoverEmptyMCPsOnStartup() {
	servers, err := s.m.pg.ListMCP()
	if err != nil {
		log.Printf("[mcp] auto-discovery at startup: failed to read the list: %v", err)
		return
	}
	s.discoverEmptyMCPs(servers, 90*time.Second)
}

func (s *Server) discoverEmptyMCPs(servers []*db.MCPServer, timeout time.Duration) {
	for _, m := range servers {
		if !m.Enabled || len(m.Tools) > 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, timeout)
		if err := s.discoverAndCacheMCP(ctx, m); err != nil {
			log.Printf("[mcp] auto-discovery of %s at startup failed: %v", m.Name, err)
		}
		cancel()
	}
}
