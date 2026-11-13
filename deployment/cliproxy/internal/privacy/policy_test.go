package privacy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
)

type stubTransport struct {
	calls    int
	respBody string
}

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls++
	if r.Body != nil {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(s.respBody)),
		Request:    r,
	}, nil
}

type memSink struct{ recs []Record }

func (m *memSink) Record(r Record) error {
	r.Body = append([]byte(nil), r.Body...)
	m.recs = append(m.recs, r)
	return nil
}

type failSink struct{}

func (failSink) Record(Record) error { return errors.New("disk full") }

const cleanBody = `{"model":"claude-x","messages":[{"role":"user","content":"hello"}]}`

func newTestPolicy(t *testing.T, stub http.RoundTripper, sink Sink) (http.RoundTripper, contract.Receipts) {
	t.Helper()
	rc, err := NewReceipts(filepath.Join(t.TempDir(), "receipt.key"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := NewPolicy(PolicyConfig{Identifiers: []string{"m1nervac0nsole"}, Receipts: rc, Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	return pol(stub), rc
}

func messagesRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestZeroConfigRejected(t *testing.T) {
	if _, err := NewPolicy(PolicyConfig{}); err == nil {
		t.Fatal("zero config disabled privacy policy")
	}
}

func TestPartialConfigRejected(t *testing.T) {
	if _, err := NewPolicy(PolicyConfig{Identifiers: []string{"m1nervac0nsole"}}); err == nil {
		t.Fatal("partial config accepted")
	}
}

func TestCleanInferencePassesAndIsCaptured(t *testing.T) {
	stub := &stubTransport{respBody: `{"ok":true}`}
	sink := &memSink{}
	rt, _ := newTestPolicy(t, stub, sink)
	resp, err := rt.RoundTrip(messagesRequest(t, cleanBody))
	if err != nil {
		t.Fatalf("clean request denied: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if stub.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", stub.calls)
	}
	if len(sink.recs) != 2 || sink.recs[0].Direction != DirectionRequest || sink.recs[1].Direction != DirectionResponse {
		t.Fatalf("unexpected records: %+v", sink.recs)
	}
}

func TestCanaryVariantsDenied(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("m1nervac0nsole"))
	cases := map[string]string{
		"plain":              `{"model":"m","messages":[{"role":"user","content":"ask m1nervac0nsole"}]}`,
		"zero-width":         `{"model":"m","messages":[{"role":"user","content":"AR\u200bTEX"}]}`,
		"variation-selector": `{"model":"m","messages":[{"role":"user","content":"AR\uFE0FTEX"}]}`,
		"bidi-format":        `{"model":"m","messages":[{"role":"user","content":"AR\u202ETEX"}]}`,
		"json-escape-key":    `{"model":"m","messages":[],"\u0041RTEX":1}`,
		"double-escaped":     `{"model":"m","messages":[{"role":"user","content":"\\u0061rtex"}]}`,
		"base64":             `{"model":"m","messages":[{"role":"user","content":"` + b64 + `"}]}`,
	}
	for name, body := range cases {
		body := body
		t.Run(name, func(t *testing.T) {
			stub := &stubTransport{}
			rt, _ := newTestPolicy(t, stub, &memSink{})
			_, err := rt.RoundTrip(messagesRequest(t, body))
			if !errors.Is(err, contract.ErrDenied) {
				t.Fatalf("want ErrDenied, got %v", err)
			}
			if strings.Contains(strings.ToLower(err.Error()), "m1nervac0nsole") {
				t.Fatal("denial error echoed the identifier")
			}
			if stub.calls != 0 {
				t.Fatal("denied request reached upstream")
			}
		})
	}
}
func TestNativeMediaRejectedButToolSchemaAllowed(t *testing.T) {
	attachments := []string{
		`{"model":"claude-x","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"AAECAw=="}}]}]}`,
		`{"model":"g","contents":[{"parts":[{"inlineData":{"mimeType":"image/png","data":"AAECAw=="}}]}]}`,
		`{"model":"o","input":[{"type":"input_file","file_data":"AAECAw=="}]}`,
	}
	for _, body := range attachments {
		stub := &stubTransport{}
		rt, _ := newTestPolicy(t, stub, &memSink{})
		if _, err := rt.RoundTrip(messagesRequest(t, body)); !errors.Is(err, contract.ErrDenied) || stub.calls != 0 {
			t.Fatalf("attachment was not denied before dispatch: err=%v calls=%d", err, stub.calls)
		}
	}

	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, &memSink{})
	body := `{"model":"claude-x","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"x","input_schema":{"type":"object","properties":{"image":{"type":"string"}}}}]}`
	if _, err := rt.RoundTrip(messagesRequest(t, body)); err != nil {
		t.Fatalf("ordinary tool schema rejected: %v", err)
	}
}

func TestGzipBodyScanned(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`{"model":"m","messages":[{"role":"user","content":"m1nervac0nsole"}]}`))
	zw.Close()
	req := messagesRequest(t, "")
	req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, &memSink{})
	if _, err := rt.RoundTrip(req); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if stub.calls != 0 {
		t.Fatal("denied request reached upstream")
	}
}

func TestUnknownEncodingDenied(t *testing.T) {
	req := messagesRequest(t, cleanBody)
	req.Header.Set("Content-Encoding", "gzip, br")
	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, &memSink{})
	if _, err := rt.RoundTrip(req); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestMultipartDenied(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages",
		strings.NewReader("--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nhi\r\n--b--\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, &memSink{})
	if _, err := rt.RoundTrip(req); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestUnlistedRoutesDenied(t *testing.T) {
	urls := map[string]string{
		"other path": "https://api.anthropic.com/v1/files",
		"plain http": "http://api.anthropic.com/v1/messages",
		"port":       "https://api.anthropic.com:443/v1/messages",
		"other host": "https://evil.example/v1/messages",
	}
	for name, u := range urls {
		u := u
		t.Run(name, func(t *testing.T) {
			parsed, err := http.NewRequest(http.MethodPost, u, strings.NewReader(cleanBody))
			if err != nil {
				t.Fatal(err)
			}
			parsed.Header.Set("Content-Type", "application/json")
			stub := &stubTransport{}
			rt, _ := newTestPolicy(t, stub, &memSink{})
			if _, err := rt.RoundTrip(parsed); !errors.Is(err, contract.ErrDenied) {
				t.Fatalf("want ErrDenied, got %v", err)
			}
			if stub.calls != 0 {
				t.Fatal("denied request reached upstream")
			}
		})
	}
}

func TestHostHeaderMismatchDenied(t *testing.T) {
	req := messagesRequest(t, cleanBody)
	req.Host = "evil.example"
	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, &memSink{})
	if _, err := rt.RoundTrip(req); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestEmptyInferenceBodyDenied(t *testing.T) {
	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, &memSink{})
	if _, err := rt.RoundTrip(messagesRequest(t, "")); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestOversizeInferenceBodyDenied(t *testing.T) {
	big := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("a", maxInferenceBody) + `"}]}`
	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, &memSink{})
	if _, err := rt.RoundTrip(messagesRequest(t, big)); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if stub.calls != 0 {
		t.Fatal("oversize request reached upstream")
	}
}

func TestSinkFailureDeniesBeforeSend(t *testing.T) {
	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, failSink{})
	if _, err := rt.RoundTrip(messagesRequest(t, cleanBody)); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if stub.calls != 0 {
		t.Fatal("request reached upstream despite capture failure")
	}
}

func TestResponseCaptureBounded(t *testing.T) {
	big := strings.Repeat("a", maxInferenceBody+10)
	stub := &stubTransport{respBody: big}
	sink := &memSink{}
	rt, _ := newTestPolicy(t, stub, sink)
	resp, err := rt.RoundTrip(messagesRequest(t, cleanBody))
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n != int64(len(big)) {
		t.Fatalf("copied %d bytes, err %v", n, err)
	}
	resp.Body.Close()
	last := sink.recs[len(sink.recs)-1]
	if last.Direction != DirectionResponse || !last.Complete || !last.Truncated || len(last.Body) != maxInferenceBody {
		t.Fatalf("bad response record: dir=%s complete=%v truncated=%v len=%d",
			last.Direction, last.Complete, last.Truncated, len(last.Body))
	}
}

func TestReplayRequiresVerifiedReceipt(t *testing.T) {
	state := "enc-state-opaque-1"
	binding := contract.Binding{Provider: contract.ProviderClaude, Model: "claude-x", Profile: "1", SessionID: "s1", CredentialID: "grant-a"}
	block := `{"type":"thinking","thinking":"associated visible text","signature":"` + state + `"}`
	body := `{"model":"claude-x","messages":[{"role":"assistant","content":[` + block + `]}]}`
	stateJSON := `{"type":"assistant","content":[` + block + `]}`

	stub := &stubTransport{}
	rt, rc := newTestPolicy(t, stub, &memSink{})
	receipt, err := rc.Sign(binding, []byte(stateJSON))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rt.RoundTrip(messagesRequest(t, body)); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("opaque state without turn: want ErrDenied, got %v", err)
	}

	ctx := WithTurn(context.Background(), Turn{Binding: binding, Replay: []Replayed{{State: []byte(stateJSON), Receipt: receipt}}})
	if _, err := rt.RoundTrip(messagesRequest(t, body).WithContext(ctx)); err != nil {
		t.Fatalf("verified replay denied: %v", err)
	}
	mutatedBody := `{"model":"claude-x","messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"changed visible text","signature":"` + state + `"}]}]}`
	if _, err := rt.RoundTrip(messagesRequest(t, mutatedBody).WithContext(ctx)); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("mutated associated content replay: want ErrDenied, got %v", err)
	}

	wrongCredential := binding
	wrongCredential.CredentialID = "grant-b"
	wrongCredentialCtx := WithTurn(context.Background(), Turn{Binding: wrongCredential, Replay: []Replayed{{State: []byte(stateJSON), Receipt: receipt}}})
	if _, err := rt.RoundTrip(messagesRequest(t, body).WithContext(wrongCredentialCtx)); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("wrong credential replay: want ErrDenied, got %v", err)
	}

	foreign := binding
	foreign.SessionID = "s2"
	foreignCtx := WithTurn(context.Background(), Turn{Binding: foreign, Replay: []Replayed{{State: []byte(stateJSON), Receipt: receipt}}})
	if _, err := rt.RoundTrip(messagesRequest(t, body).WithContext(foreignCtx)); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("foreign-binding replay: want ErrDenied, got %v", err)
	}

	mismatchCtx := WithTurn(context.Background(), Turn{Binding: binding, Replay: []Replayed{{State: []byte(`{"type":"assistant","content":[{"type":"thinking","thinking":"mutated","signature":"` + state + `"}]}`), Receipt: receipt}}})
	if _, err := rt.RoundTrip(messagesRequest(t, body).WithContext(mismatchCtx)); !errors.Is(err, contract.ErrDenied) {
		t.Fatalf("uncovered opaque state: want ErrDenied, got %v", err)
	}
}
func TestReplayRejectsOpaqueTransplantBetweenBlocks(t *testing.T) {
	binding := contract.Binding{Provider: contract.ProviderClaude, Model: "claude-x", Profile: "1", SessionID: "s", CredentialID: "grant"}
	original := `{"type":"assistant","content":[{"type":"thinking","thinking":"first","signature":"sig-a"},{"type":"thinking","thinking":"second","signature":"sig-b"}]}`
	swapped := `{"model":"claude-x","messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"first","signature":"sig-b"},{"type":"thinking","thinking":"second","signature":"sig-a"}]}]}`
	rc, err := NewReceipts(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := rc.Sign(binding, []byte(original))
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubTransport{}
	rt, _ := newTestPolicy(t, stub, &memSink{})
	ctx := WithTurn(context.Background(), Turn{Binding: binding, Replay: []Replayed{{State: []byte(original), Receipt: receipt}}})
	if _, err := rt.RoundTrip(messagesRequest(t, swapped).WithContext(ctx)); !errors.Is(err, contract.ErrDenied) || stub.calls != 0 {
		t.Fatalf("transplanted opaque state reached upstream: err=%v calls=%d", err, stub.calls)
	}
}
