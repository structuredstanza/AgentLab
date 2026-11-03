package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestMCPStartupContinuesAfterSSESetupDeadline(t *testing.T) {
	fixture, _, _ := trafficEvidenceServer(t)
	s := &Server{m: fixture.m, ctx: context.Background()}
	exited, release := make(chan struct{}), make(chan struct{})
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(exited)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release); stalled.CloseClientConnections(); stalled.Close() })
	messages := make(chan []byte, 4)
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: endpoint\ndata: http://%s/message\n\n", r.Host)
			w.(http.Flusher).Flush()
			for {
				select {
				case payload := <-messages:
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
					w.(http.Flusher).Flush()
				case <-r.Context().Done():
					return
				}
			}
		}
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		if req.ID == 0 {
			return
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "healthy", "version": "1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "health_probe", "description": "Inspect health", "inputSchema": map[string]any{"type": "object"}}}}
		default:
			http.Error(w, "unexpected request", 400)
			return
		}
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		messages <- payload
	}))
	t.Cleanup(healthy.Close)
	rows := []*db.MCPServer{
		{Name: t.Name() + "-stalled", Transport: "sse", URL: stalled.URL + "/sse", Enabled: true},
		{Name: t.Name() + "-healthy", Transport: "sse", URL: healthy.URL + "/sse", Enabled: true},
	}
	for _, row := range rows {
		id, err := s.m.pg.SaveMCP(row)
		if err != nil {
			t.Fatal(err)
		}
		row.ID = id
		t.Cleanup(func() {
			if err := s.m.pg.DeleteMCP(id); err != nil {
				t.Error(err)
			}
		})
	}
	finished := make(chan struct{})
	go func() { s.discoverEmptyMCPs(rows, 200*time.Millisecond); close(finished) }()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("stalled MCP blocked the next startup server")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("timed-out setup request leaked")
	}
	stored, err := s.m.pg.ListMCP()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range stored {
		if row.ID == rows[0].ID && (row.LastConnectOK == nil || *row.LastConnectOK) {
			t.Fatal("stalled MCP was not marked unhealthy")
		}
		if row.ID == rows[1].ID {
			if row.LastConnectOK == nil || !*row.LastConnectOK {
				t.Fatalf("healthy MCP was not discovered: %+v", row)
			}
			found := false
			for _, name := range row.Tools {
				if strings.Contains(name, "health_probe") {
					found = true
				}
			}
			if !found {
				t.Fatal("healthy MCP tool cache was not populated")
			}
		}
	}
}
