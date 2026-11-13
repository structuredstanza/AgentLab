package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/config"
)

// TestPostgresDSNErrorKeepsIdentifiers pins that the missing-config startup error
// keeps the identifiers an operator must act on verbatim (not translated).
func TestPostgresDSNErrorKeepsIdentifiers(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("M1NERVAC0NSOLE_PG_DSN", "")
	t.Setenv("M1NERVAC0NSOLE_CONFIG", filepath.Join(dir, "nope.json"))

	_, _, err := config.PostgresDSN()
	if err == nil {
		t.Fatal("missing config should error")
	}
	for _, want := range []string{"M1NERVAC0NSOLE_PG_DSN", "database", "dsn", "host/user/dbname"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("startup error should keep identifier %q verbatim: %q", want, err.Error())
		}
	}
}

// TestPostgresDSNSourceNamesWinner pins that the source label reports which
// configuration source supplied the DSN.
func TestPostgresDSNSourceNamesWinner(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	t.Setenv("M1NERVAC0NSOLE_CONFIG", filepath.Join(dir, "nope.json"))
	t.Setenv("M1NERVAC0NSOLE_PG_DSN", "postgres://envwins/x")
	if _, source, err := config.PostgresDSN(); err != nil {
		t.Fatalf("env source: %v", err)
	} else if !strings.Contains(source, "M1NERVAC0NSOLE_PG_DSN") {
		t.Errorf("env source label should name M1NERVAC0NSOLE_PG_DSN: %q", source)
	}

	t.Setenv("M1NERVAC0NSOLE_PG_DSN", "")
	if err := os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("M1NERVAC0NSOLE_CONFIG", cfgPath)
	if _, source, err := config.PostgresDSN(); err != nil {
		t.Fatalf("dsn source: %v", err)
	} else if !strings.Contains(source, "database.dsn") {
		t.Errorf("dsn source label should name database.dsn: %q", source)
	}

	if err := os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","dbname":"d","user":"u"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, source, err := config.PostgresDSN(); err != nil {
		t.Fatalf("fields source: %v", err)
	} else if !strings.Contains(source, "database") {
		t.Errorf("fields source label should name the database fields: %q", source)
	}
}
