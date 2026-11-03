package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadBearerCapability(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		mode    os.FileMode
		want    string
		wantErr bool
	}{
		{name: "exact", content: "native-fixture-capability", mode: 0o600, want: "native-fixture-capability"},
		{name: "surrounding whitespace", content: " \tnative-fixture-capability\r\n", mode: 0o600, want: "native-fixture-capability"},
		{name: "empty", mode: 0o600, wantErr: true},
		{name: "whitespace only", content: " \r\n\t", mode: 0o600, wantErr: true},
		{name: "group readable", content: "native-fixture-capability", mode: 0o640, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capability")
			if err := os.WriteFile(path, []byte(tc.content), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			got, err := readBearerCapability(path)
			defer clear(got)
			if tc.wantErr {
				if err == nil || got != nil {
					t.Fatal("unsafe or empty capability file was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatal("capability file whitespace was not normalized")
			}
		})
	}
}
