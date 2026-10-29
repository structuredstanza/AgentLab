package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestSyncScopeSentryFormattedLocalized exercises the exact Sprintf/Errorf format
// strings used by the sync handler so a verb mismatch or a reverted literal is
// caught by running the real format operation (not just inspecting the constant).
func TestSyncScopeSentryFormattedLocalized(t *testing.T) {
	ds := fmt.Errorf(errSSDataSourceMissingFmt, scopeSentryMCPName).Error()
	if !strings.Contains(ds, scopeSentryMCPName) {
		t.Fatalf("the data source name disappeared: %q", ds)
	}

	noURL := fmt.Errorf(errSSDataSourceNoURLFmt, scopeSentryMCPName).Error()
	if !strings.Contains(noURL, scopeSentryMCPName) {
		t.Fatalf("the data source name disappeared: %q", noURL)
	}

	meta := fmt.Sprintf(warnSSProjectMetaFmt, "proj-1", errors.New("boom"))
	if !strings.Contains(meta, "proj-1") || !strings.Contains(meta, "boom") {
		t.Fatalf("the project/original error was not substituted: %q", meta)
	}

	company := fmt.Sprintf(warnSSCompanyCreateFmt, "ACME", errors.New("boom"))
	if !strings.Contains(company, "ACME") {
		t.Fatalf("the company name was not substituted: %q", company)
	}

	fetch := fmt.Sprintf(errSSFetchFmt, "subdomain", "t1", errors.New("boom"))
	if !strings.Contains(fetch, "subdomain") || !strings.Contains(fetch, "t1") {
		t.Fatalf("the asset type/target was not substituted: %q", fetch)
	}

	truncated := fmt.Sprintf(warnSSTruncatedFmt, "app", "t1", syncMaxPerType)
	if !strings.Contains(truncated, "5000") {
		t.Fatalf("the upper-limit count was not substituted: %q", truncated)
	}
}

// TestSyncScopeSentryIngestParseErrors runs ssIngest on malformed JSON for each asset
// kind. The unmarshal failure returns before any store access, so this is a real code
// path (nil AssetStore never dereferenced) that must keep the asset-type prefix.
func TestSyncScopeSentryIngestParseErrors(t *testing.T) {
	s := &Server{}
	bad := json.RawMessage("not json")
	for _, kind := range []string{"subdomain", "app", "service"} {
		got := s.ssIngest(nil, kind, bad, map[string]int{})
		if got == "" {
			t.Fatalf("%s: the JSON was broken but the error string was empty", kind)
		}
		if !strings.Contains(got, kind) {
			t.Fatalf("%s: the asset type prefix disappeared: %q", kind, got)
		}
	}
}
