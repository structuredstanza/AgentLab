package manifest

import (
	"slices"
	"testing"
)

// proxyManifest is the shape every HTTP tool uses: a proxy flag and its value as
// two arguments, plus the scheme-less form.
func proxyManifest() *Manifest {
	return &Manifest{
		ID:      "proxy-test",
		Name:    "proxy test",
		Command: Command{Program: "tool", Args: []string{"--proxy", "{{ proxy }}", "--proxy-host", "{{ proxyhost }}"}},
	}
}

// A manifest that takes a proxy flag is given the run's proxy URL, and nothing at
// all when the run has none: an invented loopback proxy would send the tool's
// traffic to whatever happens to listen on that port.
func TestProxyPlaceholderRendersTheRunsProxyURL(t *testing.T) {
	m := proxyManifest()

	args, err := m.Resolve("example.test", nil, "")
	if err != nil {
		t.Fatalf("Resolve with no proxy: %v", err)
	}
	if slices.Contains(args, "http://127.0.0.1:8888") || slices.Contains(args, "127.0.0.1:8888") {
		t.Fatalf("args = %v, want no invented loopback proxy", args)
	}
	if slices.Contains(args, "http://") || slices.Contains(args, "https://") {
		t.Fatalf("args = %v, want no empty scheme", args)
	}

	args, err = m.Resolve("example.test", nil, "http://credential@127.0.0.1:8788")
	if err != nil {
		t.Fatalf("Resolve with a gateway: %v", err)
	}
	want := []string{"--proxy", "http://credential@127.0.0.1:8788", "--proxy-host", "credential@127.0.0.1:8788"}
	if !slices.Equal(args, want) {
		t.Fatalf("args = %v, want %v", args, want)
	}

	// A proxy URL without an http(s) scheme keeps its value, and the host form
	// still loses the scheme rather than handing the tool a URL as a host.
	args, err = m.Resolve("example.test", nil, "socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Resolve with a socks5 gateway: %v", err)
	}
	want = []string{"--proxy", "socks5://127.0.0.1:1080", "--proxy-host", "127.0.0.1:1080"}
	if !slices.Equal(args, want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

// An empty proxy must not turn into a dangling flag when the manifest uses the
// flag+value form: both arguments disappear together.
func TestProxyPlaceholderFlagFormDropsWhenUnset(t *testing.T) {
	m := &Manifest{
		ID:      "proxy-flag-form",
		Name:    "proxy flag form",
		Command: Command{Program: "tool", Args: []string{"-u", "{{ target.value }}", "{{ proxy | --proxy }}"}},
	}
	args, err := m.Resolve("example.test", nil, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{"-u", "example.test"}; !slices.Equal(args, want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
}
