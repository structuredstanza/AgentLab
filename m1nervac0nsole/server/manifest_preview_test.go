package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func previewManifest(t *testing.T, key, body string) (int, map[string]any) {
	t.Helper()
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/tools/{key}/preview", s.previewToolManifest)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/tools/"+key+"/preview", strings.NewReader(body)))
	var out map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("preview body: %v", err)
		}
	}
	return rec.Code, out
}

// The preview must be the argv the executor would run, including the manifest
// defaults the operator never typed: a form that shows only the typed values
// would hide the flags the tool actually gets.
func TestPreviewRendersTheExecutedArgv(t *testing.T) {
	code, out := previewManifest(t, "nmap", `{"target":"10.0.0.5","params":{"ports":"22,80"}}`)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if out["program"] != "nmap" {
		t.Fatalf("program = %v", out["program"])
	}
	args, _ := out["args"].([]any)
	got := make([]string, len(args))
	for i, a := range args {
		got[i], _ = a.(string)
	}
	// ports is overridden, timing and service come from the defaults.
	want := []string{"-oX", "-", "-p", "22,80", "-T4", "-sV", "10.0.0.5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	effective, _ := out["effective"].(map[string]any)
	if effective["service"] != "true" || effective["timing"] != "T4" {
		t.Fatalf("defaults not applied to effective: %v", effective)
	}
}

func TestPreviewRejectsBadInput(t *testing.T) {
	if code, _ := previewManifest(t, "nope", `{"target":"10.0.0.5"}`); code != http.StatusNotFound {
		t.Fatalf("unknown tool status = %d", code)
	}
	if code, _ := previewManifest(t, "nmap", `{"params":{}}`); code != http.StatusBadRequest {
		t.Fatalf("missing target status = %d", code)
	}
	if code, _ := previewManifest(t, "nmap", `{"target":"10.0.0.5","params":{"timing":"T9"}}`); code != http.StatusBadRequest {
		t.Fatalf("invalid enum status = %d", code)
	}
	if code, _ := previewManifest(t, "nmap", `not json`); code != http.StatusBadRequest {
		t.Fatalf("bad body status = %d", code)
	}
}
