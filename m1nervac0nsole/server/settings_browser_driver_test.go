package server

import "testing"

// An unknown driver would silently fall back to the MCP surface at assembly
// time, so the setter refuses it instead of storing a value nothing understands.
func TestSetBrowserDriverRejectsUnknownValue(t *testing.T) {
	m := &Manager{}
	for _, v := range []string{"", "Native", "playwright", "chromium"} {
		if err := m.SetBrowserDriver(v); err == nil {
			t.Errorf("SetBrowserDriver(%q) accepted", v)
		}
	}
}
