// Package enrich is the engine-side (non-AI) asset auto-completion layer: an
// async worker pool that resolves domains (dnsx) and probes web assets (HTTP)
// and writes the results back into the asset graph — creating IP/port nodes,
// resolves/exposes edges, and filling attrs.dns / attrs.http.
//
// Outbound HTTP probes must leave masked: the masking egress proxy (`artex
// egress-proxy`) owns the TLS fingerprint and the browser identity the target
// sees. Every probe, and every redirect hop, goes directly to it and trusts its
// CA explicitly; verification is never disabled. When no proxy/CA is configured
// or the proxy is unreachable the probe fails — there is no direct fallback and
// no detour through any other proxy.
//
// Capture is first-party and does not depend on a second proxy: Options.Observe
// receives each hop as the client saw it (with explicit truncation), and the
// manager stores it in the traffic store when capture is on.
//
// The engine is shared by every task on the manager, so scope is enforced here,
// at dispatch: a job carries the task it was discovered under, and a destination
// excluded by that task's boundary (or by an intercept block rule) is never
// contacted — including a redirect destination. A job without task context is
// dropped rather than enriched on behalf of no task. DNS resolution is ungated by
// RoE (§5.2) but still honours an explicit exclusion, since resolving a host the
// operator ruled out is contact the operator did not authorize.
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

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/egress"
	"github.com/structuredstanza/AgentLab/artex-global/useragent"

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

// Engine owns the resolver, the masking-proxy HTTP client, and the worker pool.
type Engine struct {
	as      *db.AssetStore
	resolv  *dnsx.DNSX
	proxy   string       // masking egress proxy URL (may carry credentials; never logged raw)
	client  *http.Client // nil = HTTP probing disabled (httpOff says why)
	httpOff string

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

// Options configures an Engine.
type Options struct {
	// Workers is the pool size; <=0 means 4.
	Workers int
	// Proxy is the masking egress proxy URL. Empty resolves from
	// ARTEX_EGRESS_PROXY. There is deliberately NO built-in default: a fixed
	// loopback port may belong to an unrelated listener, and a probe sent there
	// would not be masked (it could even be logged by whatever answers).
	Proxy string
	// CAFile is the proxy's PEM CA. Empty resolves from ARTEX_EGRESS_CA, then
	// SSL_CERT_FILE. A missing or unparseable CA disables HTTP probing rather than
	// falling back to unverified TLS.
	CAFile string
	// Observe, if set, receives every request/response pair the engine exchanged
	// with the proxy, one per hop (redirects included), plus transport failures.
	// It must be cheap and must not call back into the engine.
	Observe func(Observation)
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

	envEgressProxy = "ARTEX_EGRESS_PROXY"
	envEgressCA    = "ARTEX_EGRESS_CA"
)

// MaskFromEnv returns the explicitly configured masking egress proxy and its CA
// file: ARTEX_EGRESS_PROXY / ARTEX_EGRESS_CA, with SSL_CERT_FILE as the CA
// fallback (the guest supervisor points it at the egress CA). Either may be
// empty; the caller decides what an empty proxy means (here: no HTTP probing).
func MaskFromEnv() (proxy, caFile string) {
	proxy = strings.TrimSpace(os.Getenv(envEgressProxy))
	caFile = strings.TrimSpace(os.Getenv(envEgressCA))
	if caFile == "" {
		caFile = strings.TrimSpace(os.Getenv("SSL_CERT_FILE"))
	}
	return proxy, caFile
}

// New builds the engine. HTTP probing is disabled (fail closed) when there is no
// explicitly configured masking egress proxy or no usable CA; DNS still runs.
// Returns a usable engine even if the resolver fails to init (DNS becomes a
// no-op).
func New(as *db.AssetStore, opts Options) *Engine {
	workers := opts.Workers
	if workers <= 0 {
		workers = 4
	}
	proxy := strings.TrimSpace(opts.Proxy)
	envProxy, envCA := MaskFromEnv()
	if proxy == "" {
		proxy = envProxy
	}
	caFile := strings.TrimSpace(opts.CAFile)
	if caFile == "" {
		caFile = envCA
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
		proxy:  proxy,
		jobs:   make(chan job, queueSize),
		cool:   map[string]time.Time{},
		closed: make(chan struct{}),
	}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	if proxy == "" {
		e.httpOff = fmt.Sprintf("no masking egress proxy configured (%s; no assumed default, no direct fallback)", envEgressProxy)
	} else if client, err := buildClient(proxy, caFile, opts.Observe); err != nil {
		e.httpOff = errDetail(err, proxy).Error() + " (no direct fallback)"
	} else {
		client.CheckRedirect = e.checkRedirect
		e.client = client
	}
	if e.client == nil {
		log.Printf("[enrich] HTTP probing disabled: %s", e.httpOff)
	} else {
		log.Printf("[enrich] HTTP probes exit via the masking egress proxy %s (CA verified; observed=%v)", RedactProxyURL(proxy), opts.Observe != nil)
	}
	e.workersWG.Add(workers)
	for range workers {
		go e.worker()
	}
	return e
}

// buildClient returns an HTTP client that sends every request, and every
// redirect hop, directly to the masking egress proxy. The proxy's CA is appended
// to the system pool, so HTTPS verification stays on (the proxy re-signs the leaf
// for the CONNECT authority, IP literals included). An absent or unusable CA is
// an error, not a reason to skip verification.
func buildClient(proxy, caFile string, observe func(Observation)) (*http.Client, error) {
	u, err := url.Parse(proxy)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid egress proxy %q", RedactProxyURL(proxy))
	}
	if caFile == "" {
		return nil, fmt.Errorf("no CA configured for %s (%s or %s); HTTPS through it would not verify", RedactProxyURL(proxy), envEgressCA, "SSL_CERT_FILE")
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("egress CA %s is unreadable: %w", caFile, err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("egress CA %s contains no certificates", caFile)
	}
	var rt http.RoundTripper = &http.Transport{
		Proxy:               http.ProxyURL(u),
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives:   true,
		DisableCompression:  true, // decoding is done in doHTTP, so Observe sees raw bytes for every encoding
		TLSHandshakeTimeout: httpTimeout,
	}
	if observe != nil {
		rt = &observingTransport{base: rt, observe: observe, secret: proxy}
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
	if u, err := url.Parse(target); err == nil && u.Scheme != "" && u.Host != "" {
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
	return true, ""
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
	client := e.client
	if client == nil {
		// No masked route: the probe is skipped rather than sent directly.
		log.Printf("[enrich] http %s (task %d) skipped: %s", host, taskID, e.httpOff)
		return
	}
	ctx, cancel := context.WithTimeout(withTaskID(e.ctx, taskID), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		log.Printf("[enrich] http %s (task %d): %v", host, taskID, errDetail(err, rawURL))
		return
	}
	useragent.SetIfAbsent(req.Header.Set, req.Header.Get("User-Agent"))
	resp, err := client.Do(req)
	if err != nil {
		// The masking route is the only way out; a failure here is final (there is
		// no direct retry), and the URL may carry credentials, so only the host and
		// the scrubbed cause are logged.
		log.Printf("[enrich] http %s (task %d) via %s: %v", host, taskID, RedactProxyURL(e.proxy), errDetail(err, rawURL, e.proxy))
		return
	}
	defer resp.Body.Close()
	// The proxy answers a CONNECT before it dials the target, so a failure it
	// hit on the way can arrive here as an ordinary response. The header says
	// so; storing that status would record the proxy's failure as the site's
	// answer and bump last_seen for a host that never answered.
	if origin := resp.Header.Get(egress.HeaderEgress); origin != "" {
		log.Printf("[enrich] http %s (task %d): egress proxy reported %s; the target did not answer", host, taskID, origin)
		return
	}
	// The masking proxy forwards the origin's Content-Encoding untouched and the
	// transport does not decode, so undo it here (gzip, deflate, br). Reading at
	// most maxBodyBytes+1 DECODED bytes bounds the work whatever the compression
	// ratio, and the extra byte makes truncation detectable. A failed read is a
	// failed probe: a partial body must not be stored as if it were the response.
	var body []byte
	undecodable := false
	dec, encoded, derr := decodeBody(resp.Header.Get("Content-Encoding"), resp.Body)
	switch {
	case errors.Is(derr, errUnsupportedEncoding):
		undecodable = true // status and headers are still real; no title from compressed bytes
	case derr != nil:
		log.Printf("[enrich] http %s (task %d): decoding the response failed: %v", host, taskID, errDetail(derr, rawURL, e.proxy))
		return
	default:
		var rerr error
		body, rerr = io.ReadAll(io.LimitReader(dec, maxBodyBytes+1))
		if rerr != nil {
			log.Printf("[enrich] http %s (task %d): reading the response failed: %v", host, taskID, errDetail(rerr, rawURL, e.proxy))
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
		return err
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
