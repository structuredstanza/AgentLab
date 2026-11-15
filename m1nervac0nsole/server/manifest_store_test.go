package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

const storeTestCustomTOML = `id = "srvtest-custom"
name = "Store test"
description = "Template saved by a server test"
category = "recon"
accepts = ["domain"]
requires = ["echo"]

[command]
program = "echo"
args = ["{{ target.value }}"]
timeout_seconds = 5

[emit]
parser = "lines"
fields = ["value"]

[install]
script = "echo installing-store-test"
`

// manifestStoreServer is a DB-backed server whose stored templates are removed
// again, so a failed assertion cannot leak a template into the next test.
func manifestStoreServer(t *testing.T) (*Server, string) {
	t.Helper()
	m, s, token := memoryTestServer(t)
	t.Cleanup(func() {
		for _, id := range []string{"dig", "srvtest-custom", "srvtest-bad"} {
			_, _ = m.pg.DeleteToolManifest(context.Background(), id)
		}
	})
	// A leftover row from an interrupted run would change what "builtin" means.
	for _, id := range []string{"dig", "srvtest-custom", "srvtest-bad"} {
		_, _ = m.pg.DeleteToolManifest(context.Background(), id)
	}
	if err := s.reloadManifests(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, token
}

// catalog returns the listed tools keyed by id.
func catalog(t *testing.T, s *Server, token string) map[string]map[string]any {
	t.Helper()
	code, out := memoryAPI(t, s, token, http.MethodGet, "/api/tool-manifests", "")
	if code != http.StatusOK {
		t.Fatalf("list status %d: %v", code, out)
	}
	list, _ := out["tools"].([]any)
	byID := map[string]map[string]any{}
	for _, raw := range list {
		tool, _ := raw.(map[string]any)
		byID[tool["id"].(string)] = tool
	}
	return byID
}

func previewArgs(t *testing.T, s *Server, token, id string) string {
	t.Helper()
	code, out := memoryAPI(t, s, token, http.MethodPost, "/api/tools/"+id+"/preview", `{"target":"example.com"}`)
	if code != http.StatusOK {
		t.Fatalf("preview status %d: %v", code, out)
	}
	args, _ := json.Marshal(out["args"])
	return string(args)
}

func saveBody(t *testing.T, toml string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"toml": toml})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Saving a changed copy of a built-in must change what the executor and the
// preview use, and deleting the stored row must bring the shipped version back.
func TestSavedBuiltinCopyOverridesAndDeleteRestores(t *testing.T) {
	s, token := manifestStoreServer(t)
	src, ok := manifest.BuiltinSource("dig")
	if !ok {
		t.Fatal("dig is not a built-in")
	}
	if tool := catalog(t, s, token)["dig"]; tool["source"] != "builtin" || tool["toml"] != src || tool["installable"] != false {
		t.Fatalf("unmodified dig = source %v installable %v", tool["source"], tool["installable"])
	}
	if strings.Contains(previewArgs(t, s, token, "dig"), "+tries=1") {
		t.Fatal("the shipped dig already carries the edit")
	}

	edited := strings.Replace(src, `"+short"`, `"+short", "+tries=1"`, 1)
	code, out := memoryAPI(t, s, token, http.MethodPost, "/api/tool-manifests", saveBody(t, edited))
	if code != http.StatusOK || out["id"] != "dig" {
		t.Fatalf("save status %d: %v", code, out)
	}
	if !strings.Contains(previewArgs(t, s, token, "dig"), "+tries=1") {
		t.Fatal("preview does not use the saved template")
	}
	tool := catalog(t, s, token)["dig"]
	if tool["source"] != "modified" || tool["toml"] != edited {
		t.Fatalf("saved dig = source %v", tool["source"])
	}

	code, out = memoryAPI(t, s, token, http.MethodDelete, "/api/tool-manifests/dig", "")
	if code != http.StatusOK || out["deleted"] != "dig" {
		t.Fatalf("delete status %d: %v", code, out)
	}
	if strings.Contains(previewArgs(t, s, token, "dig"), "+tries=1") {
		t.Fatal("deleting the override did not restore the built-in")
	}
	if tool := catalog(t, s, token)["dig"]; tool["source"] != "builtin" {
		t.Fatalf("restored dig source = %v", tool["source"])
	}
	// The row is gone, and a pure built-in has nothing stored to delete.
	if code, _ = memoryAPI(t, s, token, http.MethodDelete, "/api/tool-manifests/dig", ""); code != http.StatusNotFound {
		t.Fatalf("second delete status %d, want 404", code)
	}
	if code, _ = memoryAPI(t, s, token, http.MethodDelete, "/api/tool-manifests/nmap", ""); code != http.StatusNotFound {
		t.Fatalf("deleting a pure built-in status %d, want 404", code)
	}
}

func TestCustomTemplateIsListedAndInstallable(t *testing.T) {
	s, token := manifestStoreServer(t)
	builtins := len(catalog(t, s, token))

	if code, out := memoryAPI(t, s, token, http.MethodPost, "/api/tool-manifests", saveBody(t, storeTestCustomTOML)); code != http.StatusOK {
		t.Fatalf("save status %d: %v", code, out)
	}
	tools := catalog(t, s, token)
	tool := tools["srvtest-custom"]
	if tool == nil || tool["source"] != "custom" || tool["installable"] != true || len(tools) != builtins+1 {
		t.Fatalf("custom template not listed correctly: %v (catalog %d, was %d)", tool, len(tools), builtins)
	}

	code, out := memoryAPI(t, s, token, http.MethodPost, "/api/tool-manifests/srvtest-custom/install", "")
	if code != http.StatusOK {
		t.Fatalf("install status %d: %v", code, out)
	}
	// Without the boundary the install is refused, not run unisolated.
	if out["is_error"] != true || !strings.Contains(out["provenance"].(map[string]any)["verification"].(string), "isolated execution is unavailable") {
		t.Fatalf("install without a boundary: %v", out)
	}

	// With the boundary installed, the operator's button takes the same path as
	// the curator's toolbox_install: an install-purpose session, not a bare bash.
	f := &fakeExecbox{result: execbox.Result{Output: []byte("installing-store-test\n")}}
	useFakeExecbox(t, f)
	code, out = memoryAPI(t, s, token, http.MethodPost, "/api/tool-manifests/srvtest-custom/install", "")
	if code != http.StatusOK || out["is_error"] != false || out["available"] != true ||
		!strings.Contains(out["output"].(string), "installing-store-test") {
		t.Fatalf("install status %d: %v", code, out)
	}
	if f.calls != 1 || f.sess.Purpose != netpolicy.PurposeInstall {
		t.Fatalf("the HTTP install did not use the install session: calls=%d session=%+v", f.calls, f.sess)
	}
}

// An invalid template is the operator's to fix (400, with Check's message), and
// a stored row that no longer passes Check must not take the built-ins with it.
func TestInvalidTemplatesNeverHideBuiltins(t *testing.T) {
	s, token := manifestStoreServer(t)
	builtins := len(catalog(t, s, token))

	code, out := memoryAPI(t, s, token, http.MethodPost, "/api/tool-manifests", saveBody(t, "bogus = 1\n"+storeTestCustomTOML))
	if code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "unknown keys") {
		t.Fatalf("invalid save status %d: %v", code, out)
	}

	if err := s.m.pg.UpsertToolManifest(context.Background(), "srvtest-bad", "this is not [toml"); err != nil {
		t.Fatal(err)
	}
	if err := s.reloadManifests(context.Background()); err != nil {
		t.Fatalf("a broken stored row must be skipped, not fail the reload: %v", err)
	}
	tools := catalog(t, s, token)
	if len(tools) != builtins || tools["srvtest-bad"] != nil || tools["nmap"] == nil {
		t.Fatalf("catalog after a broken row: %d tools (want %d), bad listed: %v", len(tools), builtins, tools["srvtest-bad"] != nil)
	}
}

func TestInstallWithoutScriptIsRejected(t *testing.T) {
	s, token := manifestStoreServer(t)
	if code, _ := memoryAPI(t, s, token, http.MethodPost, "/api/tool-manifests/nmap/install", ""); code != http.StatusBadRequest {
		t.Fatalf("install without a script status %d, want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPost, "/api/tool-manifests/no-such-tool/install", ""); code != http.StatusNotFound {
		t.Fatalf("install of an unknown tool status %d, want 404", code)
	}
}
