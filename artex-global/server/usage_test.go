package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/nativeproxy"
)

func TestUsageStatusFailurePreservesLastGoodAsStale(t *testing.T) {
	const profileID = int64(9876543211)
	var statusCode atomic.Int32
	var connected atomic.Bool
	statusCode.Store(http.StatusOK)
	connected.Store(true)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case fmt.Sprintf("/v1/profiles/%d/status", profileID):
			if code := statusCode.Load(); code != http.StatusOK {
				w.WriteHeader(int(code))
				_, _ = w.Write([]byte(`{}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"connected":%t}`, connected.Load())
		case fmt.Sprintf("/v1/profiles/%d/usage", profileID):
			_, _ = w.Write([]byte(`{"provider":"codex","plan":"Pro","fetched_at":"2026-10-30T12:00:00.000Z","windows":[{"id":"five_hour","label":"5-Hour Session","used_fraction":1,"remaining_fraction":0,"resets_at":null}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer proxy.Close()

	client, err := nativeproxy.New(proxy.URL, "synthetic-test-token")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{nativeProxy: client}
	p := &db.LLMProfile{ID: profileID, Name: "synthetic", AuthMethod: "codex"}

	first := s.getOrFetchUsage(context.Background(), p)
	if !first.Connected || first.Stale || len(first.Windows) != 1 || first.Windows[0].RemainingFraction != 0 {
		t.Fatalf("initial usage = %+v, want fresh exhausted quota", first)
	}

	statusCode.Store(http.StatusBadGateway)
	stale := s.getOrFetchUsage(context.Background(), p)
	if !stale.Connected || !stale.Stale || stale.Error != "status_unavailable" || stale.FetchedAt == nil || len(stale.Windows) != 1 || stale.Windows[0].RemainingFraction != 0 {
		t.Fatalf("status failure usage = %+v, want stale last-good exhausted quota", stale)
	}

	statusCode.Store(http.StatusOK)
	connected.Store(false)
	disconnected := s.getOrFetchUsage(context.Background(), p)
	if disconnected.Connected || disconnected.Stale || disconnected.Error != "" || len(disconnected.Windows) != 0 {
		t.Fatalf("disconnected usage = %+v, want no quota and no stale cache", disconnected)
	}
}
