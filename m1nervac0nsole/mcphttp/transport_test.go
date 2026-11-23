package mcphttp

import "testing"

// MCP servers are operator-configured control plane: never via the env proxy.
func TestDirectTransportIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	for _, insecure := range []bool{false, true} {
		tr := directTransport(insecure)
		if tr.Proxy != nil {
			t.Fatalf("insecure=%v: transport has a Proxy func", insecure)
		}
		if got := tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify; got != insecure {
			t.Fatalf("insecure=%v: InsecureSkipVerify = %v", insecure, got)
		}
	}
}
