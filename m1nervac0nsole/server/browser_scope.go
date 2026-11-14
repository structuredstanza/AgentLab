package server

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// browserScopeCacheTTL is how long one host's scope decision is reused. A page
// with two hundred requests to one host costs one lookup, and a scope change
// made mid-run still takes effect within a minute.
const browserScopeCacheTTL = time.Minute

// browserRequestScope returns the per-request check the driver runs before a
// request leaves the browser. It is the boundary the tool guard cannot provide:
// the guard judges the URL argument and the landing page, but a redirect, an
// image, an XHR or a click's subresource is fetched before either is known.
//
// The decision is cached per host because interception sits on the hot path of
// every request the page makes.
func (s *Server) browserRequestScope(taskID string) func(string) error {
	id, err := parseTaskID(taskID)
	if err != nil {
		// Fail closed: a browser with no resolvable task cannot be scoped.
		return func(string) error { return fmt.Errorf("the task id is invalid, so the boundary cannot be checked") }
	}
	checker := db.NewTaskScopeChecker(s.m.Assets(), id)
	var mu sync.Mutex
	cache := map[string]scopeDecision{}
	return func(rawURL string) error {
		if localScheme(rawURL) {
			// data:, blob: and about: never leave the browser, so judging them
			// as hosts would break ordinary pages without protecting anything.
			return nil
		}
		host, refusal := browserURLHost(rawURL)
		if refusal != "" {
			return fmt.Errorf("%s", refusal)
		}
		mu.Lock()
		if d, ok := cache[host]; ok && time.Since(d.at) < browserScopeCacheTTL {
			mu.Unlock()
			return d.err
		}
		mu.Unlock()
		var err error
		if refusal := scopeRefusal(checker, host); refusal != "" {
			err = fmt.Errorf("%s", refusal)
		}
		mu.Lock()
		cache[host] = scopeDecision{at: time.Now(), err: err}
		mu.Unlock()
		return err
	}
}

// scopeDecision is one cached host verdict.
type scopeDecision struct {
	at  time.Time
	err error
}

// localScheme reports whether a URL is handled inside the browser and never
// reaches the network.
func localScheme(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "data", "blob", "about", "javascript", "chrome", "chrome-extension", "devtools":
		return true
	}
	return false
}
