// Package enrich is the engine-side (non-AI) asset auto-completion layer: an
// async worker pool that resolves domains (dnsx) and probes web assets (HTTP)
// and writes the results back into the asset graph — creating IP/port nodes,
// resolves/exposes edges, and filling attrs.dns / attrs.http.
//
// Outbound HTTP probes go through the recording proxy under a backend-issued
// session for the task being enriched (Options.Route): the gateway owns the TLS
// fingerprint and, for an enrichment session, the browser-shaped headers, and
// the recorder stores each exchange. Every probe, and every redirect hop, goes
// to it and trusts its CA explicitly; verification is never disabled. With no
// route, session or recorder the probe is skipped — there is no direct
// fallback and no detour through any other proxy.
//
// The engine is shared by every task on the manager, so scope is enforced here,
// at dispatch: a job carries the task it was discovered under, and a destination
// excluded by that task's boundary (or by an intercept block rule) is never
// contacted — including a redirect destination. A job without task context is
// dropped rather than enriched on behalf of no task. DNS resolution is ungated by
// RoE (§5.2) but still honours an explicit exclusion, since resolving a host the
// operator ruled out is contact the operator did not authorize. An HTTP probe
// also asks the network policy, so only a destination the task's own authorized
// rules cover is contacted; no authorizer means no probe.
package enrich

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/gateway"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/useragent"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

type jobKind int

const (
	jobDNS  jobKind = iota // resolve a domain
	jobHTTP                // probe a web asset (site)
)

type job struct {
	kind   jobKind
	taskID int64  // task the asset was discovered under; 0 = no context (dropped)
	id     int64  // asset id (domain for DNS, site for HTTP)
	arg    string // host (DNS) or url (HTTP)
}

// RedactProxyURL returns scheme://host of a proxy URL with any credentials
// dropped, for logs. An unparseable value is replaced entirely, never echoed.
func RedactProxyURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "<unparseable proxy>"
	}
	return u.Scheme + "://" + u.Host
}

// Engine owns the resolver, the recorder route, and the worker pool.
type Engine struct {
	as      *db.AssetStore
	resolv  *dnsx.DNSX
	route   Route                // nil = HTTP probing disabled
	auth    netpolicy.Authorizer // nil = every HTTP probe is refused
	jobs    chan job
	wg      sync.WaitGroup // one count per accepted job, for Wait
	coolMu  sync.Mutex
	cool    map[string]time.Time // dedup/cooldown: "kind:task:id" -> last run
	coolOps int

	// Lifecycle: lifeMu orders enqueue against Close, so no job is accepted once
	// closing is set and every accepted job is either run or released by Close.
	lifeMu    sync.Mutex
	closing   bool
	once      sync.Once
	closed    chan struct{}
	ctx       context.Context // cancelled by Close; parents every probe
	cancel    context.CancelFunc
	workersWG sync.WaitGroup
}

// Route issues the recorder session a probe for taskID runs under and returns
// the proxy URL carrying its credential, the CA that verifies the recorder's
// leaves, and a release that revokes the session. An error means no probe: there
// is no direct path.
type Route func(ctx context.Context, taskID int64) (proxyURL, caFile string, release func(), err error)

// Options configures an Engine.
type Options struct {
	// Workers is the pool size; <=0 means 4.
	Workers int
	// Route supplies each HTTP probe's recorder session. Nil disables HTTP
	// probing (DNS still runs).
	Route Route
	// Authorizer is the network-policy gate every HTTP probe asks before it
	// dials. nil refuses every probe: a destination no policy answered for is
	// not authorized, and enrichment is outbound contact like any other.
	Authorizer netpolicy.Authorizer
}

const (
	cooldown    = 5 * time.Minute
	httpTimeout = 12 * time.Second
	queueSize   = 1024
	// maxRedirects caps a followed chain; beyond it the last response is recorded.
	maxRedirects = 5
	// maxBodyBytes caps how much of a response body is read for the title.
	maxBodyBytes = 1 << 20
	// Dedup state is bounded: sweep expired keys periodically and evict when the
	// map still exceeds maxCoolEntries, so a long engagement cannot grow it
	// without limit.
	maxCoolEntries = 8192
	coolSweepEvery = 512
)

// New builds the engine. HTTP probing is disabled (fail closed) when there is no
// recorder route; DNS still runs. Returns a usable engine even if the resolver
// fails to init (DNS becomes a no-op).
func New(as *db.AssetStore, opts Options) *Engine {
	workers := opts.Workers
	if workers <= 0 {
		workers = 4
	}

	resolv, err := dnsx.New(dnsx.Options{
		BaseResolvers: dnsx.DefaultResolvers,
		MaxRetries:    3,
		QuestionTypes: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME},
		Timeout:       4 * time.Second,
	})
	if err != nil {
		log.Printf("[enrich] dnsx initialization failed; DNS resolution disabled: %v", err)
		resolv = nil
	}
	e := &Engine{
		as:     as,
		resolv: resolv,
		route:  opts.Route,
		auth:   opts.Authorizer,
		jobs:   make(chan job, queueSize),
		cool:   map[string]time.Time{},
		closed: make(chan struct{}),
	}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	if e.route == nil {
		log.Printf("[enrich] HTTP probing disabled: no recorder session route is configured (no direct fallback)")
	}
	e.workersWG.Add(workers)
	for range workers {
		go e.worker()
	}
	return e
}

// buildClient returns an HTTP client that sends every request, and every
// redirect hop, to the recorder. Its CA is appended to the system pool, so HTTPS
// verification stays on. An absent or unusable proxy or CA is an error, not a
// reason to skip verification or dial directly.
func buildClient(proxy, caFile string) (*http.Client, error) {
	u, err := url.Parse(proxy)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid recorder proxy %q", RedactProxyURL(proxy))
	}
	if caFile == "" {
		return nil, fmt.Errorf("no CA for %s; HTTPS through it would not verify", RedactProxyURL(proxy))
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("recorder CA %s is unreadable: %w", caFile, err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("recorder CA %s contains no certificates", caFile)
	}
	rt := &http.Transport{
		Proxy:               http.ProxyURL(u),
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives:   true,
		DisableCompression:  true, // decoding is done in doHTTP for every encoding
		TLSHandshakeTimeout: httpTimeout,
	}
	return &http.Client{Transport: rt, Timeout: httpTimeout}, nil
}

// ResolveDomain enqueues a DNS resolution for a domain asset. host is the FQDN;
// taskID is the task the asset was discovered under (0 drops the job). No-op for
// an empty engine.
func (e *Engine) ResolveDomain(taskID, id int64, host string) {
	e.enqueue(job{kind: jobDNS, taskID: taskID, id: id, arg: host})
}

// ProbeSite enqueues an HTTP probe for a web-asset (site). rawURL is the site URL;
// taskID is the task the asset was discovered under (0 drops the job).
func (e *Engine) ProbeSite(taskID, id int64, rawURL string) {
	e.enqueue(job{kind: jobHTTP, taskID: taskID, id: id, arg: rawURL})
}

func (e *Engine) enqueue(j job) {
	if e == nil || id0(j.id) || strings.TrimSpace(j.arg) == "" {
		return
	}
	if j.taskID <= 0 {
		// Enrichment is an outbound request; without a task there is no boundary
		// to check it against, so it must not run. This is the queue-bypass guard.
		log.Printf("[enrich] dropped job kind=%d asset=%d: no task context to check the target against", j.kind, j.id)
		return
	}
	e.lifeMu.Lock()
	defer e.lifeMu.Unlock()
	if e.closing {
		return // shut down: nothing new is accepted, so nothing can be stranded
	}
	e.wg.Add(1)
	select {
	case e.jobs <- j:
	default: // queue full → drop (best-effort enrichment)
		e.wg.Done()
		log.Printf("[enrich] queue full; dropped job kind=%d asset=%d task=%d", j.kind, j.id, j.taskID)
	}
}

// Wait blocks until every job accepted so far has been processed or released by
// Close. It does not stop the engine; call it only once enqueuers have quiesced.
func (e *Engine) Wait() {
	if e == nil {
		return
	}
	e.wg.Wait()
}

func id0(id int64) bool { return id <= 0 }

// Close shuts the engine down (idempotent). It rejects new jobs, cancels
// in-flight probes, waits for the workers to exit, then releases every job still
// queued, so on return nothing is running, nothing is queued and Wait cannot
// block. Callers must not hold a lock the Observe callback takes.
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.once.Do(func() {
		e.lifeMu.Lock()
		e.closing = true
		e.lifeMu.Unlock()
		e.cancel()
		close(e.closed)
		e.workersWG.Wait()
		for {
			select {
			case <-e.jobs:
				e.wg.Done()
			default:
				return
			}
		}
	})
}

func (e *Engine) worker() {
	defer e.workersWG.Done()
	for {
		select {
		case <-e.closed:
			return
		case j := <-e.jobs:
			e.run(j)
			e.wg.Done()
		}
	}
}

// run checks authorization before claiming a cooldown slot, so a refused job
// does not suppress a legitimate retry after the task resumes.
func (e *Engine) run(j job) {
	if allowed, reason := e.allow(j.taskID, j.arg); !allowed {
		log.Printf("[enrich] skipped job kind=%d asset=%d task=%d: %s", j.kind, j.id, j.taskID, reason)
		return
	}
	if e.onCooldown(j) {
		return
	}
	switch j.kind {
	case jobDNS:
		e.doDNS(j.taskID, j.id, j.arg)
	case jobHTTP:
		e.doHTTP(j.taskID, j.id, j.arg)
	}
}

// onCooldown returns true (skip) if this (kind,task,id) ran within the cooldown
// window. The task is part of the key: one task's refused job must not suppress
// another task's legitimate probe of the same asset.
func (e *Engine) onCooldown(j job) bool {
	key := strconv.Itoa(int(j.kind)) + ":" + itoa(j.taskID) + ":" + itoa(j.id)
	now := time.Now()

	e.coolMu.Lock()
	defer e.coolMu.Unlock()
	e.coolOps++
	if e.coolOps >= coolSweepEvery || len(e.cool) > maxCoolEntries {
		e.coolOps = 0
		for k, t := range e.cool {
			if now.Sub(t) >= cooldown {
				delete(e.cool, k)
			}
		}
		// Even after the sweep the map can exceed the cap when a burst outruns the
		// cooldown window. Drop arbitrary entries rather than grow without bound;
		// dedup is best-effort, so a lost key only costs one extra probe.
		for k := range e.cool {
			if len(e.cool) <= maxCoolEntries {
				break
			}
			delete(e.cool, k)
		}
	}
	if t, ok := e.cool[key]; ok && now.Sub(t) < cooldown {
		return true
	}
	e.cool[key] = now
	return false
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// allow is the dispatch-level scope check. It runs for the initial request and
// again for every redirect destination, so a redirect cannot walk out of the
// task's boundary. A read failure refuses the request: "could not check" must
// never mean "allowed".
func (e *Engine) allow(taskID int64, target string) (bool, string) {
	if taskID <= 0 {
		return false, "no task context to check the target against"
	}
	if e.as == nil {
		return false, "asset store unavailable, so the target cannot be checked"
	}
	host := targetHost(target)
	if host == "" {
		return false, "target host could not be parsed"
	}
	// Task state first: a missing, deleted, archived, paused, queued or finished
	// task has no scope rows, which would otherwise read as "nothing excluded".
	// This is the early refusal for the request and for every redirect hop; the
	// write is separately guarded atomically (see store).
	if live, reason, err := e.as.TaskLive(taskID); err != nil {
		return false, "task state could not be read: " + errDetail(err).Error()
	} else if !live {
		return false, reason
	}
	if checker := db.NewTaskScopeChecker(e.as, taskID); checker != nil {
		if out, reason := checker.Judge(host); out {
			return false, reason
		}
	}
	block, err := e.as.ListAssetInterceptRules()
	if err != nil {
		return false, "asset intercept rules unavailable: " + err.Error()
	}
	taskBlock, allowRules, err := e.as.TaskInterceptRulesSplit(taskID)
	if err != nil {
		return false, "task asset intercept rules unavailable: " + err.Error()
	}
	block = append(block, taskBlock...)
	var domains, ips, urls []string
	// A bare host (DNS job) is matched as a host; only a real URL is offered to
	// the URL rules, so a fuzzy_url pattern cannot match a hostname by accident.
	u, uerr := url.Parse(target)
	isURL := uerr == nil && u.Scheme != "" && u.Host != ""
	if isURL {
		urls = append(urls, target)
	}
	if net.ParseIP(host) != nil {
		ips = append(ips, host)
	} else {
		domains = append(domains, host)
	}
	if d := db.EvaluateAssetGate(block, allowRules, domains, ips, urls); !d.Allowed {
		return false, d.Reason
	}
	// The checks above only know operator exclusions and intercept blocks; the
	// network policy is the grant. A DNS job resolves a name and never contacts
	// the target, so it keeps the documented ungated behaviour; an HTTP probe
	// asks before it dials, and a redirect hop asks again through this function.
	if isURL {
		if dec := e.authorize(taskID, u); !dec.Allow {
			return false, "network policy: " + dec.Reason
		}
	}
	return true, ""
}

// authorize asks the network policy whether this task may reach the probe
// destination. No authorizer means no answer, and no answer refuses.
func (e *Engine) authorize(taskID int64, u *url.URL) netpolicy.Decision {
	if e.auth == nil {
		return netpolicy.Decision{Stage: netpolicy.StagePolicy, Reason: "no network-policy authorizer is configured"}
	}
	scheme := strings.ToLower(u.Scheme)
	proto := "http"
	if scheme == "ws" || scheme == "wss" {
		proto = "ws"
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	if port == 0 {
		switch scheme {
		case "http", "ws":
			port = 80
		case "https", "wss":
			port = 443
		}
	}
	s := netpolicy.Session{ID: "enrich:" + itoa(taskID), TaskID: taskID, Purpose: netpolicy.PurposeTesting}
	return e.auth.Authorize(e.ctx, s, netpolicy.Destination{Scheme: scheme, Host: u.Hostname(), Port: port, Protocol: proto})
}

// checkRedirect re-checks a redirect destination before it is contacted. An
// out-of-boundary (or unparseable/unknown-task) destination stops the chain and
// the last in-boundary response is recorded instead.
func (e *Engine) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	taskID, ok := taskIDFromContext(req.Context())
	if !ok {
		return http.ErrUseLastResponse
	}
	if allowed, reason := e.allow(taskID, req.URL.String()); !allowed {
		log.Printf("[enrich] redirect not followed for task %d: %s", taskID, reason)
		return http.ErrUseLastResponse
	}
	return nil
}

type taskIDContextKey struct{}

func withTaskID(ctx context.Context, taskID int64) context.Context {
	return context.WithValue(ctx, taskIDContextKey{}, taskID)
}

func taskIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(taskIDContextKey{}).(int64)
	return id, ok && id > 0
}

// ---- DNS ----

func (e *Engine) doDNS(taskID, id int64, host string) {
	if e.resolv == nil || e.as == nil {
		return
	}
	data, err := e.resolv.QueryMultiple(host)
	if err != nil || data == nil {
		if err != nil {
			log.Printf("[enrich] dns %s (task %d): %v", host, taskID, errDetail(err))
		}
		return
	}
	ips := uniq(append(append([]string{}, data.A...), data.AAAA...))
	// Each write is its own live-task transaction, so one bad record cannot abort
	// the others and none can land after the task is deleted or stopped.
	for _, ip := range ips {
		e.store(taskID, host, "resolved ip", func(sc *db.AssetStore) error {
			_, err := sc.UpsertIP(db.UpsertIPReq{IP: ip, BoundDomains: []string{host}, TaskID: taskID})
			return err
		})
	}
	records := []struct {
		typ    string
		values []string
	}{{"A", data.A}, {"AAAA", data.AAAA}, {"CNAME", data.CNAME}}
	for _, rec := range records {
		for _, v := range rec.values {
			e.store(taskID, host, rec.typ+" record", func(sc *db.AssetStore) error {
				_, err := sc.UpsertSubdomain(db.UpsertSubdomainReq{Domain: host, RecordType: rec.typ, RecordValue: []string{v}, TaskID: taskID})
				return err
			})
		}
	}
}

// store runs one asset write for a task inside db.AssetStore.WithLiveTask: the
// task row is locked and re-verified in the same transaction as the write, so a
// task deleted, stopped or paused while a slow request was in flight cannot get
// an asset (re)created or an orphan task id attached. A refusal is expected, not
// an error worth more than one line.
func (e *Engine) store(taskID int64, host, what string, fn func(*db.AssetStore) error) {
	err := e.as.WithLiveTask(taskID, fn)
	switch {
	case err == nil:
	case errors.Is(err, db.ErrTaskNotLive):
		log.Printf("[enrich] %s for %s (task %d) discarded: %v", what, host, taskID, errDetail(err))
	default:
		log.Printf("[enrich] store %s for %s (task %d): %v", what, host, taskID, errDetail(err))
	}
}

// ---- HTTP probe ----

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (e *Engine) doHTTP(taskID, id int64, rawURL string) {
	if e.as == nil {
		return
	}
	host := targetHost(rawURL)
	if host == "" {
		return
	}
	if e.route == nil {
		// No recorder route: the probe is skipped rather than sent directly.
		log.Printf("[enrich] http %s (task %d) skipped: no recorder session route is configured (no direct fallback)", host, taskID)
		return
	}
	ctx, cancel := context.WithTimeout(withTaskID(e.ctx, taskID), httpTimeout)
	defer cancel()
	// One session per probe, revoked when it ends, so the credential never
	// outlives the request it was issued for.
	proxyURL, caFile, release, err := e.route(ctx, taskID)
	if err != nil {
		log.Printf("[enrich] http %s (task %d) skipped: no recorder session (%v; no direct fallback)", host, taskID, errDetail(err))
		return
	}
	defer release()
	client, err := buildClient(proxyURL, caFile)
	if err != nil {
		log.Printf("[enrich] http %s (task %d) skipped: %v (no direct fallback)", host, taskID, errDetail(err, proxyURL))
		return
	}
	client.CheckRedirect = e.checkRedirect
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		log.Printf("[enrich] http %s (task %d): %v", host, taskID, errDetail(err, rawURL))
		return
	}
	useragent.SetIfAbsent(req.Header.Set, req.Header.Get("User-Agent"))
	// The probe decodes the body itself (decodeBody), so it names every coding
	// it handles; the gateway's navigation mask fills Accept-Encoding only when
	// the caller left it out.
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := client.Do(req)
	if err != nil {
		// The recorder is the only way out; a failure here is final (there is no
		// direct retry), and the URL may carry credentials, so only the host and
		// the scrubbed cause are logged.
		log.Printf("[enrich] http %s (task %d) via %s: %v", host, taskID, RedactProxyURL(proxyURL), errDetail(err, rawURL, proxyURL))
		return
	}
	defer resp.Body.Close()
	// The gateway answers a refused or failed origin dial itself and names the
	// stage in a header; storing that status would record the gateway's refusal
	// as the site's answer and bump last_seen for a host that never answered.
	if stage := resp.Header.Get(gateway.HeaderStage); stage != "" {
		log.Printf("[enrich] http %s (task %d): the gateway refused or failed the request at %s; the target did not answer", host, taskID, stage)
		return
	}
	// The probe advertised every coding it decodes, so the masker forwards the
	// origin's Content-Encoding untouched and the transport does not decode:
	// undo it here (gzip, deflate, br). Reading at most maxBodyBytes+1 DECODED
	// bytes bounds the work whatever the compression ratio, and the extra byte
	// makes truncation detectable. A failed read is a failed probe: a partial
	// body must not be stored as if it were the response.
	var body []byte
	undecodable := false
	dec, encoded, derr := decodeBody(resp.Header.Get("Content-Encoding"), resp.Body)
	switch {
	case errors.Is(derr, errUnsupportedEncoding):
		undecodable = true // status and headers are still real; no title from compressed bytes
	case derr != nil:
		log.Printf("[enrich] http %s (task %d): decoding the response failed: %v", host, taskID, errDetail(derr, rawURL, proxyURL))
		return
	default:
		var rerr error
		body, rerr = io.ReadAll(io.LimitReader(dec, maxBodyBytes+1))
		if rerr != nil {
			log.Printf("[enrich] http %s (task %d): reading the response failed: %v", host, taskID, errDetail(rerr, rawURL, proxyURL))
			return
		}
	}
	truncated := len(body) > maxBodyBytes
	if truncated {
		body = body[:maxBodyBytes]
	}
	if !undecodable && !truncated {
		// A decoder may stop before the transport sees the end of the (small)
		// compressed body; drain the remainder so the wire observation can be
		// marked complete.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	}
	statusCode := resp.StatusCode
	// Content length: the declared length for an uncoded response that states
	// one, else the measured DECODED length, and only when the whole body was
	// read. A compressed size or a capped prefix is never reported as the length.
	var bodyLen *int64
	switch {
	case undecodable:
	case !encoded && resp.ContentLength >= 0:
		n := resp.ContentLength
		bodyLen = &n
	case !truncated:
		n := int64(len(body))
		bodyLen = &n
	}
	title := ""
	if !undecodable {
		title = extractTitle(body)
	}
	e.store(taskID, host, "probe result", func(sc *db.AssetStore) error {
		_, err := sc.UpsertHTTPService(db.UpsertHTTPServiceReq{
			URL:           rawURL,
			StatusCode:    &statusCode,
			ContentLength: bodyLen,
			PageTitle:     title,
			TaskID:        taskID,
		})
		if err != nil {
			return err
		}
		// The target answered, so any "unreachable" marker on it is stale. The
		// clear runs on this transaction on purpose: the upsert above locks the
		// asset row, so the same UPDATE over the pool would wait on our own
		// uncommitted write until the closure returns - never.
		return sc.ClearUnreachable(host)
	})
}

var reURLUserinfo = regexp.MustCompile(`://[^/\s@]*@`)

// errDetail strips the request URL net/http wraps around transport errors and
// scrubs any remaining occurrence of the given secrets (a probe URL, a proxy
// URL) and of URL userinfo, so a logged failure cannot leak query-string or
// proxy credentials.
func errDetail(err error, secrets ...string) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		err = uerr.Err
	}
	msg := err.Error()
	for _, s := range secrets {
		if s = strings.TrimSpace(s); s != "" {
			msg = strings.ReplaceAll(msg, s, "<redacted>")
		}
	}
	return errors.New(reURLUserinfo.ReplaceAllString(msg, "://<redacted>@"))
}

func extractTitle(body []byte) string {
	m := reTitle.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

// targetHost returns the hostname of a URL, or of a bare host[:port], without
// resolving anything. Empty when the value carries no usable host.
func targetHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	h := raw
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(strings.TrimSpace(h), "[]")
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
