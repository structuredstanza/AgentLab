package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/mcphttp"
	"github.com/structuredstanza/norma/mcp"
	actool "github.com/structuredstanza/norma/tool"
)

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
		return mcp.NewStdioClient(ctx, m.Name, m.Command, jsonStrMap(m.Env), jsonStrSlice(m.Args)...)
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
