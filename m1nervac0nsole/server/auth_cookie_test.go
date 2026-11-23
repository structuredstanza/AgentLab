package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The UI keeps a non-secret marker cookie for the Next.js route guard, and the
// backend sets an HttpOnly stream cookie so browser SSE GETs never need the JWT
// in a URL. The stream cookie must authenticate nothing else: a cookie the
// browser attaches by itself must never authorize a mutation or a general API
// call. Bearer and ?token= keep working for every client.
func TestAuthCookieScope(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}, jwtKey: []byte("cookie-ingress-test-key")}
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"path":"probe"}`

	do := func(method, path, payload string, credential func(*http.Request)) *httptest.ResponseRecorder {
		var src io.Reader
		if payload != "" {
			src = strings.NewReader(payload)
		}
		req := httptest.NewRequest(method, path, src)
		if payload != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		credential(req)
		// The log stream ends on the first context cancellation; a cancelled
		// request keeps the test from blocking on the live tail.
		ctx, cancel := context.WithCancel(req.Context())
		cancel()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req.WithContext(ctx))
		return rec
	}
	mutation := func(credential func(*http.Request)) *httptest.ResponseRecorder {
		return do(http.MethodPost, "/api/workspace/mkdir", body, credential)
	}
	stream := func(credential func(*http.Request)) *httptest.ResponseRecorder {
		return do(http.MethodGet, "/api/logs/stream?since=0", "", credential)
	}

	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	query := func(r *http.Request) { r.URL.RawQuery = "token=" + tok }
	streamCookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: streamCookieName, Value: tok}) }
	marker := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: authCookieName, Value: "1"}) }

	// Explicit credentials keep working everywhere, including mutations; a bearer
	// call also re-issues the stream cookie so a browser that lacks it can open SSE.
	if rec := mutation(bearer); rec.Code != http.StatusOK {
		t.Fatalf("bearer mutation: status=%d body=%s", rec.Code, rec.Body.String())
	} else if c := rec.Result().Cookies(); len(c) != 1 || c[0].Name != streamCookieName || c[0].Value != tok {
		t.Fatalf("bearer call did not re-issue the stream cookie: %v", c)
	}
	if rec := mutation(query); rec.Code != http.StatusOK {
		t.Fatalf("query-token mutation: status=%d body=%s", rec.Code, rec.Body.String())
	} else if c := rec.Result().Cookies(); len(c) != 0 {
		t.Fatalf("query-token call set cookies: %v", c)
	}
	if rec := stream(bearer); rec.Code != http.StatusOK {
		t.Fatalf("bearer stream: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := stream(query); rec.Code != http.StatusOK {
		t.Fatalf("query-token stream: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// The stream cookie is a credential for read-only SSE GETs...
	if rec := stream(streamCookie); rec.Code != http.StatusOK {
		t.Fatalf("stream-cookie stream: status=%d body=%s", rec.Code, rec.Body.String())
	}
	// ...and for nothing else: not a mutation, not a general API read.
	if rec := mutation(streamCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stream-cookie mutation: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, "/api/stats", "", streamCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stream-cookie non-stream GET: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// The marker the UI writes is not a credential anywhere.
	if rec := mutation(marker); rec.Code != http.StatusUnauthorized {
		t.Fatalf("marker-cookie mutation: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := stream(marker); rec.Code != http.StatusUnauthorized {
		t.Fatalf("marker-cookie stream: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := stream(func(*http.Request) {}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous stream: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// The stream cookie must be unreadable by page scripts and unusable from another
// site; both properties are what make it safe to leave out of the URL.
func TestStreamCookieAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	setStreamCookie(rec, "header.payload.signature")
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	c := cookies[0]
	if c.Name != streamCookieName || c.Value != "header.payload.signature" {
		t.Fatalf("name/value: %+v", c)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge != int(jwtTTL.Seconds()) {
		t.Fatalf("attributes: %+v", c)
	}
}

// Logging out must drop the stream cookie: no page script can clear an HttpOnly
// cookie, so the server has to, or a logged-out browser keeps a live credential.
func TestLogoutClearsStreamCookie(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}, jwtKey: []byte("cookie-ingress-test-key")}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout: status=%d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != streamCookieName || cookies[0].Value != "" {
		t.Fatalf("logout cookies: %v", cookies)
	}
	if h := rec.Header().Get("Set-Cookie"); !strings.Contains(h, "Max-Age=0") || !strings.Contains(h, "HttpOnly") {
		t.Fatalf("logout Set-Cookie: %q", h)
	}
}
