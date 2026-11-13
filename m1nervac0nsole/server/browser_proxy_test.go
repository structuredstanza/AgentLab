package server

import (
	"reflect"
	"testing"
)

// The browser MCP's proxy flags are rebuilt from capture state on every start,
// so the strip must remove every form of them — including the bare
// --ignore-https-errors that lets Chromium accept the recorder's certificate.
func TestStripProxyArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nothing to strip", []string{"@playwright/mcp", "--headless"}, []string{"@playwright/mcp", "--headless"}},
		{
			"value form plus certificate flag",
			[]string{"@playwright/mcp", "--proxy-server", "http://127.0.0.1:8788", "--ignore-https-errors", "--headless"},
			[]string{"@playwright/mcp", "--headless"},
		},
		{
			"equals form",
			[]string{"--proxy-server=http://x:1", "--proxy-bypass=a.com,b.com", "--headless"},
			[]string{"--headless"},
		},
		{"only proxy args", []string{"--proxy-server", "http://x:1", "--ignore-https-errors"}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripProxyArgs(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("stripProxyArgs(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
