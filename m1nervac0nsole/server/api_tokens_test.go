package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// apiTokenTask creates a task for a token test and registers its cleanup.
func apiTokenTask(t *testing.T, m *Manager, description string) int64 {
	t.Helper()
	task, err := m.CreateTask(description, "mcp token test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.pg.DeleteTask(tid) })
	return tid
}

func TestAPITokenRoundTrip(t *testing.T) {
	m, s, jwt := memoryTestServer(t)
	pg := m.pg
	ctx := context.Background()
	tid := apiTokenTask(t, m, "token round trip")

	code, out := memoryAPI(t, s, jwt, "POST", "/api/tokens",
		fmt.Sprintf(`{"name":"harness","task_id":%d,"ttl_hours":1}`, tid))
	if code != 201 {
		t.Fatalf("mint: %d %v", code, out)
	}
	plain, _ := out["token"].(string)
	if !strings.HasPrefix(plain, "mvn_") || len(plain) < 40 {
		t.Fatalf("plaintext token looks wrong: %q", plain)
	}
	id := int64(out["id"].(float64))
	if id <= 0 {
		t.Fatalf("mint returned no id: %v", out)
	}

	row, err := pg.AuthenticateAPIToken(ctx, plain)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if row.ID != id || row.TaskID != tid || row.Name != "harness" {
		t.Fatalf("authenticate returned the wrong row: %+v", row)
	}
	if row.LastUsedAt == nil {
		t.Fatal("authenticate did not stamp last_used_at")
	}

	code, out = memoryAPI(t, s, jwt, "GET", "/api/tokens", "")
	if code != 200 {
		t.Fatalf("list: %d %v", code, out)
	}
	items, _ := out["items"].([]any)
	found := false
	for _, item := range items {
		entry, _ := item.(map[string]any)
		if int64(entry["id"].(float64)) != id {
			continue
		}
		found = true
		if _, leaked := entry["token"]; leaked {
			t.Fatal("list leaked the plaintext token")
		}
		if _, leaked := entry["token_hash"]; leaked {
			t.Fatal("list leaked the token hash")
		}
	}
	if !found {
		t.Fatalf("minted token missing from the list: %v", items)
	}

	code, out = memoryAPI(t, s, jwt, "DELETE", fmt.Sprintf("/api/tokens/%d", id), "")
	if code != 200 || out["ok"] != true {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if _, err := pg.AuthenticateAPIToken(ctx, plain); !errors.Is(err, db.ErrAPITokenInvalid) {
		t.Fatalf("revoked token still authenticates: %v", err)
	}
}

func TestAPITokenExpiredAndValidation(t *testing.T) {
	m, s, jwt := memoryTestServer(t)
	pg := m.pg
	ctx := context.Background()
	tid := apiTokenTask(t, m, "token expiry")

	// ttl_hours is bounded; 0 means the 24h default.
	if code, out := memoryAPI(t, s, jwt, "POST", "/api/tokens",
		fmt.Sprintf(`{"name":"bad ttl","task_id":%d,"ttl_hours":721}`, tid)); code != 400 {
		t.Fatalf("ttl 721: %d %v", code, out)
	}
	if code, out := memoryAPI(t, s, jwt, "POST", "/api/tokens",
		fmt.Sprintf(`{"name":"bad task","task_id":%d,"ttl_hours":1}`, tid+1_000_000)); code != 404 {
		t.Fatalf("unknown task: %d %v", code, out)
	}
	code, out := memoryAPI(t, s, jwt, "POST", "/api/tokens", fmt.Sprintf(`{"name":"default","task_id":%d}`, tid))
	if code != 201 {
		t.Fatalf("default ttl: %d %v", code, out)
	}
	expires := out["expires_at"].(string)
	parsed, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		t.Fatalf("expires_at %q: %v", expires, err)
	}
	if d := time.Until(parsed); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("default ttl is not 24h: %v", d)
	}

	plain, row, err := pg.CreateAPIToken(ctx, "expired", tid, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE api_tokens SET expires_at=now()-interval '1 minute' WHERE id=$1`, row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.AuthenticateAPIToken(ctx, plain); !errors.Is(err, db.ErrAPITokenInvalid) {
		t.Fatalf("expired token still authenticates: %v", err)
	}
	if _, err := pg.AuthenticateAPIToken(ctx, "mvn_not-a-real-token"); !errors.Is(err, db.ErrAPITokenInvalid) {
		t.Fatalf("unknown token: %v", err)
	}
}
