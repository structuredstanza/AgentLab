package traffic

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeleteHostCannotTouchTheStore is the guard for a captured host named
// after one of the store's own directories. Deleting such a host used to rename
// the index, the blob store, the CA or the staging directory into
// _delete_staging and unlink it, because sanitize kept the leading underscore.
func TestDeleteHostCannotTouchTheStore(t *testing.T) {
	tr, dir := openTraffic(t)

	// A spilled body proves the blob store still serves its content afterwards.
	big := bytes.Repeat([]byte("x"), maxInlineBody+1)
	tr.record(newFlow("blobs.test", "GET", "/big", nil, big))
	tr.record(newFlow("_index", "GET", "/x", nil, []byte("captured")))
	var blob string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies WHERE id IN (SELECT id FROM exchanges WHERE host = 'blobs.test')`).Scan(&blob); err != nil {
		t.Fatalf("the large body did not spill to the blob store: %v", err)
	}

	for _, name := range []string{"_index", "_blobs", "_ca", "_delete_staging"} {
		if _, err := tr.DeleteHost(name); err != nil {
			t.Fatalf("DeleteHost(%q): %v", name, err)
		}
	}

	for _, name := range []string{"_index", "_blobs", "_ca"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("the store's %s directory did not survive the deletion: %v", name, err)
		}
	}
	// The index still answers, and only the other host's exchange is left.
	var hosts []string
	rows, err := tr.DB().Query(`SELECT DISTINCT host FROM exchanges`)
	if err != nil {
		t.Fatalf("the index no longer opens: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h)
	}
	if len(hosts) != 1 || hosts[0] != "blobs.test" {
		t.Fatalf("remaining hosts = %v, want [blobs.test]", hosts)
	}
	// The blob is still readable and the CA still parses.
	if data, _, err := tr.BlobRange(blob, 0, 16); err != nil || len(data) != 16 {
		t.Fatalf("the blob store no longer serves %s: %d bytes, %v", blob, len(data), err)
	}
	pem, err := os.ReadFile(tr.CACertPath())
	if err != nil {
		t.Fatalf("the CA is gone: %v", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		t.Fatal("the CA is no longer a valid PEM certificate")
	}
}

// TestStageRefusesStoreDirectories pins the second half of the guard: staging
// refuses a source that is not a direct child host directory, so a caller that
// derives one wrongly still cannot move the store's own directories.
func TestStageRefusesStoreDirectories(t *testing.T) {
	tr, dir := openTraffic(t)
	stage, moves, err := tr.stageTrees([]string{
		filepath.Join(dir, "_index"),
		filepath.Join(dir, "_ca"),
		filepath.Join(dir, "_blobs", "sha256"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stage != "" || len(moves) != 0 {
		t.Fatalf("staged the store's own directories: stage=%q moves=%v", stage, moves)
	}
	if _, err := os.Stat(filepath.Join(dir, "_index", "index.sqlite")); err != nil {
		t.Fatalf("the index was moved: %v", err)
	}
}

// TestDeleteHostEscapesLikeWildcards proves a host is matched literally: "_"
// and "%" are LIKE wildcards, so deleting "a_b" used to delete "axb" too.
func TestDeleteHostEscapesLikeWildcards(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(newFlow("a_b", "GET", "/one", nil, []byte("1")))
	tr.record(newFlow("axb", "GET", "/two", nil, []byte("2")))

	n, err := tr.DeleteHost("a_b")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d exchanges, want 1", n)
	}
	var host string
	if err := tr.DB().QueryRow(`SELECT host FROM exchanges`).Scan(&host); err != nil {
		t.Fatalf("the unrelated host was deleted too: %v", err)
	}
	if host != "axb" {
		t.Fatalf("remaining host = %q, want axb", host)
	}
}

// TestSanitizeKeepsHostNamesForExistingStores proves the guard did not rename
// the directories of ordinary hosts: an existing on-disk store keeps working.
func TestSanitizeKeepsHostNamesForExistingStores(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":      "example.com",
		"example.com:8443": "example.com_8443",
		"_index":           "host_index",
		"_":                "root",
		"":                 "root",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	if !strings.HasPrefix(sanitize("_blobs"), "host") {
		t.Error("a host named after a store directory still collides with it")
	}
}
