package notify

import "testing"

// Delivery is direct by design: the backend's HTTP(S)_PROXY must not apply.
func TestNotifyTransportIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	if notifyTransport.Proxy != nil {
		t.Fatal("notifyTransport still has a Proxy func; delivery would follow the environment proxy")
	}
}
