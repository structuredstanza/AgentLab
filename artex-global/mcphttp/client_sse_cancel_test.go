package mcphttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLegacySSESetupCancellation(t *testing.T) {
	for _, stage := range []string{"headers", "endpoint", "initialize", "notification"} {
		t.Run(stage, func(t *testing.T) {
			ready, exited, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			messages := make(chan []byte, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sse" {
					defer close(exited)
					if stage != "headers" {
						w.Header().Set("Content-Type", "text/event-stream")
						if stage != "endpoint" {
							fmt.Fprintf(w, "event: endpoint\ndata: http://%s/message\n\n", r.Host)
						}
						w.(http.Flusher).Flush()
					}
					if stage == "headers" || stage == "endpoint" {
						close(ready)
					}
					for {
						select {
						case message := <-messages:
							fmt.Fprintf(w, "event: message\ndata: %s\n\n", message)
							w.(http.Flusher).Flush()
						case <-r.Context().Done():
							return
						case <-release:
							return
						}
					}
				}
				var req rpcRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "bad request", 400)
					return
				}
				if req.Method == "initialize" {
					w.WriteHeader(http.StatusAccepted)
					if stage == "initialize" {
						close(ready)
						return
					}
					result := json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}`)
					payload, _ := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
					messages <- payload
					return
				}
				if stage == "notification" && req.Method == "notifications/initialized" {
					close(ready)
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			t.Cleanup(func() { close(release); srv.CloseClientConnections(); srv.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				client *Client
				err    error
			}
			finished := make(chan result, 1)
			go func() { c, err := NewSSE(ctx, "fixture", srv.URL+"/sse", nil, false); finished <- result{c, err} }()
			select {
			case <-ready:
			case <-time.After(3 * time.Second):
				t.Fatal("fixture setup stage was not reached")
			}
			cancel()
			select {
			case got := <-finished:
				if got.client != nil {
					_ = got.client.Close()
					t.Fatal("cancelled setup returned a client")
				}
				if !errors.Is(got.err, context.Canceled) {
					t.Fatalf("setup cancellation: %v", got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("setup ignored caller cancellation")
			}
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("cancelled SSE request remained alive")
			}
		})
	}
}
