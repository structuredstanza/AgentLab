package server

import (
	"context"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// TestConnectMCPErrors checks that connectMCP rejects each invalid transport config with an error.
// Every branch returns before dialing, so no DB or network is needed.
func TestConnectMCPErrors(t *testing.T) {
	for _, c := range []struct {
		label string
		srv   *db.MCPServer
	}{
		{"stdio_missing_command", &db.MCPServer{Transport: "stdio", Command: ""}},
		{"http_missing_url", &db.MCPServer{Transport: "http", URL: ""}},
		{"sse_missing_url", &db.MCPServer{Transport: "sse", URL: ""}},
		{"unknown_transport_path", &db.MCPServer{Transport: "websocket"}},
	} {
		_, err := connectMCP(context.Background(), c.srv)
		if err == nil {
			t.Fatalf("%s: no error returned (validation passed)", c.label)
		}
	}
}
