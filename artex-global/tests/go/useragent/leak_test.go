package useragent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is the guard against the leak returning. Every http.NewRequest in the
// backend must be followed by an identity header, or the request goes out as
// Go-http-client/1.1 and names the stack to whoever receives it.
//
// It is a source check rather than a runtime one because the failure is silence:
// a missing header produces no error, only a request that identifies itself.
func TestEveryOutboundRequestSetsAnIdentity(t *testing.T) {
	// This guard walks the whole module, so it climbs from tests/go/useragent to
	// artex-global. It moved here from useragent/ and the depth changed with it.
	root := "../../.."
	allowed := map[string]string{
		// These either set the identity themselves or never leave the guest.
		"egress/proxy.go":        "the proxy is the identity",
		"egress/proxy_test.go":   "test fixture",
		"useragent/useragent.go": "defines the identity",
	}

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(rel, "third_party/") || strings.HasPrefix(rel, "web/") {
			return nil
		}
		if _, ok := allowed[rel]; ok {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		src := string(data)
		if !strings.Contains(src, "http.NewRequest") {
			return nil
		}
		// The file must route through the identity helper, directly or via a
		// header it sets from it.
		if strings.Contains(src, "useragent.") {
			return nil
		}
		offenders = append(offenders, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range offenders {
		t.Errorf("%s builds an HTTP request without setting an identity; it will send Go-http-client/1.1", f)
	}
}
