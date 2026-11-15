package traffic

import "testing"

func TestValidateProxyURL(t *testing.T) {
	ok := []string{
		"http://127.0.0.1:8080",
		"https://proxy.example.com:3128",
		"socks5://10.0.0.1:1080",
		"socks5://user:pass@10.0.0.1:1080",
	}
	for _, raw := range ok {
		if _, err := ValidateProxyURL(raw); err != nil {
			t.Errorf("ValidateProxyURL(%q) unexpected error: %v", raw, err)
		}
	}
	bad := []string{
		"127.0.0.1:8080",         // no scheme
		"ftp://host:21",          // unsupported scheme
		"http://",                // no host
		"socks4://10.0.0.1:1080", // unsupported scheme
	}
	for _, raw := range bad {
		if _, err := ValidateProxyURL(raw); err == nil {
			t.Errorf("ValidateProxyURL(%q) expected error, got nil", raw)
		}
	}
}

func TestProxyAddr(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		// Bare :port means "bind all interfaces" — the legacy default. The URL
		// agents consume must still point at loopback so they reach the local proxy.
		{":8788", "http://127.0.0.1:8788"},
		// Explicit loopback — the current default since #129 (open proxy exposure).
		{"127.0.0.1:8788", "http://127.0.0.1:8788"},
		// Explicit all-interface bind is still supported (remote capture via SSH).
		{"0.0.0.0:8788", "http://0.0.0.0:8788"},
	}
	for _, c := range cases {
		got := (&Traffic{addr: c.addr}).ProxyAddr()
		if got != c.want {
			t.Errorf("ProxyAddr(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}
