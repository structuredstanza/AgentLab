package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// shortcut: policy changes are polled every second, replace with DB notifications
// if sub-second revocation is required. A refresh has a one-second deadline.
const laneRefreshInterval = time.Second

type directLaneEndpoint struct {
	profile string
	raw     string
}

type directLaneClient struct {
	execbox.Client
	snapshot func(context.Context, netpolicy.Session) (*execbox.DirectLane, error)
}

// The wrapper must keep every capability of the client it wraps, or a feature
// that asserts for one (install publishing) treats isolation as unavailable.
var _ execbox.Publisher = (*directLaneClient)(nil)

// Publish delegates the staged-install publish; it needs no lane of its own.
func (c *directLaneClient) Publish(ctx context.Context, s netpolicy.Session, name string) (execbox.Published, error) {
	return execbox.PublishArtifact(c.Client, ctx, s, name)
}

type requireLaneKey struct{}

func executionSessionContext(ctx context.Context, m *Manager, sess netpolicy.Session) context.Context {
	context.AfterFunc(ctx, func() { m.RevokeSession(sess.Credential) })
	return execbox.WithSession(ctx, sess)
}

func directLaneVPNAvailable(interfaces []net.Interface) bool {
	for _, iface := range interfaces {
		if iface.Name == "tun0" && iface.Flags&(net.FlagUp|net.FlagRunning) == net.FlagUp|net.FlagRunning {
			return true
		}
	}
	return false
}

func directLaneSnapshot(pg *db.DB, ctx context.Context, sess netpolicy.Session) (*execbox.DirectLane, error) {
	if sess.Purpose != netpolicy.PurposeTesting || sess.TaskID <= 0 {
		return nil, nil
	}
	var proxy string
	if err := pg.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM settings WHERE key='global_proxy'),'')`).Scan(&proxy); err != nil {
		return nil, fmt.Errorf("direct lane exit policy: %w", err)
	}
	if strings.TrimSpace(proxy) != "" {
		return nil, nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("direct lane interfaces: %w", err)
	}
	if !directLaneVPNAvailable(interfaces) {
		return nil, nil
	}
	state, err := pg.PolicyState(ctx, sess)
	if err != nil {
		return nil, err
	}
	rows, err := pg.QueryContext(ctx, `
SELECT DISTINCT ON (endpoint) name, endpoint
FROM llm_profiles, LATERAL (VALUES (base_url), (proxy)) AS endpoints(endpoint)
WHERE COALESCE(endpoint, '') <> ''
ORDER BY endpoint, id`)
	if err != nil {
		return nil, fmt.Errorf("direct lane provider endpoints: %w", err)
	}
	var endpoints []directLaneEndpoint
	for rows.Next() {
		var endpoint directLaneEndpoint
		if err := rows.Scan(&endpoint.profile, &endpoint.raw); err != nil {
			rows.Close()
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	deny, err := directLaneDeny(ctx, endpoints, net.DefaultResolver.LookupHost)
	if err != nil {
		return nil, err
	}
	return &execbox.DirectLane{Policy: state, Egress: "tun0", Deny: deny}, nil
}

func directLaneDeny(ctx context.Context, endpoints []directLaneEndpoint, lookup func(context.Context, string) ([]string, error)) ([]string, error) {
	// Deny infrastructure addresses, not entire VPN destination networks.
	deny := []string{"127.0.0.0/8", "10.98.0.0/16", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", "::1/128"}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("direct lane local addresses: %w", err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, err
		}
		deny = append(deny, ip.String())
	}
	hosts := []string{"host.microsandbox.internal"}
	if raw := os.Getenv("M1NERVAC0NSOLE_NATIVE_PROXY_URL"); raw != "" {
		endpoints = append(endpoints, directLaneEndpoint{raw: raw})
	}
	for _, endpoint := range endpoints {
		// pgSaveProfile stores base_url as typed, and the agent layer accepts a
		// scheme-less host:port by implicitly meaning http://; url.Parse instead
		// reads "box:11434" as scheme "box" with an empty host, so a valid
		// profile would break every spawn while the VPN is up.
		raw := endpoint.raw
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			if endpoint.profile != "" {
				return nil, fmt.Errorf("direct lane: invalid endpoint for LLM profile %q", endpoint.profile)
			}
			return nil, fmt.Errorf("direct lane: invalid native proxy endpoint")
		}
		hosts = append(hosts, u.Hostname())
	}
	for _, host := range hosts {
		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("direct lane infrastructure %s: %w", host, err)
		}
		deny = append(deny, ips...)
	}
	return deny, nil
}

func (c *directLaneClient) prepare(ctx context.Context, sess netpolicy.Session, spec execbox.Spec) (context.Context, context.CancelFunc, execbox.Spec, error) {
	runCtx, cancel := context.WithCancel(ctx)
	readCtx, stop := context.WithTimeout(runCtx, laneRefreshInterval)
	lane, err := c.snapshot(readCtx, sess)
	stop()
	if err == nil && ctx.Value(requireLaneKey{}) == true && lane == nil {
		err = fmt.Errorf("direct lane became unavailable before execution")
	}
	if err != nil {
		cancel()
		return ctx, cancel, spec, err
	}
	spec.Lane = lane
	return runCtx, cancel, spec, nil
}

func (c *directLaneClient) monitor(ctx context.Context, cancel context.CancelFunc, sess netpolicy.Session) {
	defer cancel()
	ticker := time.NewTicker(laneRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Detached from the process: its exit must not turn an in-flight refresh
			// into a false policy failure, and a real failure must still be reported.
			refresh, stop := context.WithTimeout(context.WithoutCancel(ctx), laneRefreshInterval)
			lane, err := c.snapshot(refresh, sess)
			if err == nil && lane == nil {
				err = fmt.Errorf("direct lane egress no longer available")
			}
			if err == nil {
				err = execbox.SetDirectLane(refresh, c.Client, sess, lane)
			}
			stop()
			if err != nil {
				log.Printf("[execbox] direct lane session %s cancelled: %v", sess.ID, err)
				// Cancellation tears down the process and its network namespace, including
				// old rules when replacement failed. Never keep using the old grant. The
				// session's own kill stays here; a refresh failure never aborts the task's
				// shared execution context, which would land every in-flight intent as
				// blocked with an unattributed cause.
				return
			}
		}
	}
}

func (c *directLaneClient) Run(ctx context.Context, sess netpolicy.Session, spec execbox.Spec) (io.ReadWriteCloser, error) {
	return c.run(ctx, sess, spec, nil)
}

func (c *directLaneClient) RunWithFiles(ctx context.Context, sess netpolicy.Session, spec execbox.Spec, files []*os.File) (io.ReadWriteCloser, error) {
	return c.run(ctx, sess, spec, files)
}

func (c *directLaneClient) run(ctx context.Context, sess netpolicy.Session, spec execbox.Spec, files []*os.File) (io.ReadWriteCloser, error) {
	ctx, cancel, spec, err := c.prepare(ctx, sess, spec)
	if err != nil {
		return nil, err
	}
	var rw io.ReadWriteCloser
	if files == nil {
		rw, err = c.Client.Run(ctx, sess, spec)
	} else {
		rw, err = execbox.RunFiles(c.Client, ctx, sess, spec, files)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	proc, ok := execbox.ProcessOf(rw)
	if spec.Lane != nil {
		if !ok {
			cancel()
			_ = rw.Close()
			return nil, fmt.Errorf("direct lane requires process lifecycle control")
		}
		go c.monitor(ctx, cancel, sess)
	}
	if ok {
		go func() { _, _ = proc.Wait(); cancel() }()
	}
	return rw, nil
}

func (c *directLaneClient) RunOnce(ctx context.Context, sess netpolicy.Session, spec execbox.Spec) (execbox.Result, error) {
	ctx, cancel, spec, err := c.prepare(ctx, sess, spec)
	if err != nil {
		return execbox.Result{}, err
	}
	defer cancel()
	if spec.Lane != nil {
		go c.monitor(ctx, cancel, sess)
	}
	return c.Client.RunOnce(ctx, sess, spec)
}

func (c *directLaneClient) SetDirectLane(ctx context.Context, sess netpolicy.Session, lane *execbox.DirectLane) error {
	return execbox.SetDirectLane(ctx, c.Client, sess, lane)
}

// manifestDirectRoute only removes HTTP proxy flags/env for bulk HTTP tools.
// Interactive Bash and scripts retain their recorder env while raw sockets use
// the scoped lane. A selected direct manifest must refuse if egress disappears.
func (s *Server) manifestDirectRoute(ctx context.Context, mUnit string) (context.Context, bool, error) {
	if mUnit != "rps" {
		return ctx, false, nil
	}
	sess, err := execbox.RequireSession(ctx)
	if err != nil {
		return ctx, false, err
	}
	if sess.Purpose != netpolicy.PurposeTesting {
		return ctx, false, nil
	}
	client, _ := execbox.Installed()
	c, ok := client.(*directLaneClient)
	if !ok {
		return ctx, false, nil
	}
	profile, err := s.m.pg.TaskSpeedProfile(sess.TaskID)
	if err != nil {
		return ctx, false, err
	}
	if profile != db.SpeedProfileStandard && profile != db.SpeedProfileUnbound {
		return ctx, false, nil
	}
	readCtx, cancel := context.WithTimeout(ctx, laneRefreshInterval)
	defer cancel()
	lane, err := c.snapshot(readCtx, sess)
	if err != nil || lane == nil {
		return ctx, false, err
	}
	return context.WithValue(ctx, requireLaneKey{}, true), true, nil
}
