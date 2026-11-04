package privacy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/artex/cliproxyhost/internal/contract"
)

// PolicyConfig configures the required outbound admission decorator.
type PolicyConfig struct {
	// Identifiers are ARTEX identifiers and project names that must never leave the host.
	Identifiers []string
	Receipts    contract.Receipts
	Sink        Sink
}

type policy struct {
	canaries []string
	receipts contract.Receipts
	sink     Sink
}

// NewPolicy builds the decorator installed once per process.
func NewPolicy(cfg PolicyConfig) (contract.Policy, error) {
	if len(cfg.Identifiers) == 0 || cfg.Receipts == nil || cfg.Sink == nil {
		return nil, errors.New("privacy policy needs identifiers, receipts, and a sink")
	}
	p := &policy{receipts: cfg.Receipts, sink: cfg.Sink}
	for _, id := range cfg.Identifiers {
		n := normalize(id)
		if n == "" {
			return nil, errors.New("privacy policy identifiers must not be empty")
		}
		p.canaries = append(p.canaries, n)
	}
	return func(next http.RoundTripper) http.RoundTripper {
		return &policyTransport{next: next, p: p}
	}, nil
}

type policyTransport struct {
	next http.RoundTripper
	p    *policy
}

// RoundTrip admits or denies one request. Every hop of a redirect passes through here.
func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt, ok := lookupRoute(req)
	if !ok || (req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host)) {
		return deny(req)
	}
	turn, hasTurn := turnFrom(req.Context())
	if hasTurn && turn.Binding.Provider != rt.provider {
		return deny(req)
	}

	raw, err := readRequestBody(req, rt.kind)
	if err != nil {
		return deny(req)
	}
	// The canary gate keeps this host's identity out of a THIRD PARTY's hands. A local
	// upstream is reached over loopback and run by the same operator, so naming the host
	// in its prompt discloses nothing; scanning it would deny every real request, since
	// the product's own prompts name the product. Withholding the canaries disables the
	// search while shape validation, capture and receipts still apply.
	canaries := t.p.canaries
	if rt.provider == contract.ProviderLocal {
		canaries = nil
	}
	s := &scanner{canaries: canaries, budget: maxScanBudget}
	if err := s.scanHeaders(req.Header); err != nil {
		return deny(req)
	}
	if err := s.scanQuery(req.URL.RawQuery); err != nil {
		return deny(req)
	}
	decoded, err := decodeContentEncoding(req.Header.Get("Content-Encoding"), raw)
	if err != nil {
		return deny(req)
	}
	top, opaque, err := s.inspectBody(req.Header.Get("Content-Type"), decoded, rt.kind)
	if err != nil {
		return deny(req)
	}

	model := turn.Binding.Model
	if m, ok := top["model"].(string); ok {
		if hasTurn && m != turn.Binding.Model {
			return deny(req)
		}
		model = m
	}
	if rt.kind == kindInference {
		if err := verifyReplay(req.Context(), t.p.receipts, opaque); err != nil {
			return deny(req)
		}
		rec := Record{
			Direction:       DirectionRequest,
			Provider:        rt.provider,
			Model:           model,
			Profile:         turn.Binding.Profile,
			SessionID:       turn.Binding.SessionID,
			Path:            req.URL.EscapedPath(),
			ContentType:     req.Header.Get("Content-Type"),
			ContentEncoding: req.Header.Get("Content-Encoding"),
			Body:            raw,
			Complete:        true,
		}
		if err := t.p.sink.Record(rec); err != nil {
			return deny(req)
		}
	}

	out := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		out.Body = io.NopCloser(bytes.NewReader(raw))
		out.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(raw)), nil
		}
	}
	resp, err := t.next.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	if rt.kind == kindInference {
		resp.Body = newCaptureBody(resp.Body, t.p.sink, Record{
			Direction:       DirectionResponse,
			Provider:        rt.provider,
			Model:           model,
			Profile:         turn.Binding.Profile,
			SessionID:       turn.Binding.SessionID,
			Path:            req.URL.EscapedPath(),
			ContentType:     resp.Header.Get("Content-Type"),
			ContentEncoding: resp.Header.Get("Content-Encoding"),
		})
	}
	return resp, nil
}

// readRequestBody reads the whole body within the route's bound and always closes it.
func readRequestBody(req *http.Request, k kind) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	defer req.Body.Close()
	limit := int64(maxAuthBody)
	if k == kindInference {
		limit = maxInferenceBody
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, contract.ErrDenied
	}
	return raw, nil
}

// deny closes the request body and returns the fixed policy error. It never
// echoes the request.
func deny(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Body.Close()
	}
	return nil, contract.ErrDenied
}
