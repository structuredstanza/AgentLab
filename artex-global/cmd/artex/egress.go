package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/limits"
)

// runEgressProxy is the guest's outbound HTTP path, run as a separate process so
// a crash cannot take the backend with it.
//
// It is a subcommand rather than a separate binary because the guest image
// already ships one executable, and the proxy shares the identity and CA layout
// that the backend reports.
func runEgressProxy(args []string) int {
	fs := flag.NewFlagSet("egress-proxy", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8888", "listen address for the outbound proxy")
	dir := fs.String("dir", "", "directory holding the engagement CA and identity (default: <data>/egress)")
	dataDir := fs.String("data", "", "data directory, used when -dir is empty")
	caOnly := fs.Bool("print-ca", false, "print the CA certificate and exit, for installing into a trust store")
	perMinute := fs.Int("rpm", 0, "hard request ceiling per target per minute (0 disables)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	base := *dir
	if base == "" {
		root := *dataDir
		if root == "" {
			root = filepath.Join("/state", "runtime")
		}
		base = filepath.Join(root, "egress")
	}

	ca, err := egress.LoadOrCreateCA(base)
	if err != nil {
		log.Printf("egress: CA: %v", err)
		return 1
	}
	if *caOnly {
		os.Stdout.Write(ca.PEM())
		return 0
	}
	identity, err := egress.LoadIdentity(base)
	if err != nil {
		log.Printf("egress: identity: %v", err)
		return 1
	}

	// The ceiling is per target: a backlog of machines must not make each box
	// wait behind the others' budget. The scan count is global, so a backlog
	// cannot multiply the load either.
	var gate egress.Gate
	if g := limits.NewPerHostRateGate(*perMinute); g != nil {
		gate = g
	}

	proxy, err := egress.New(*addr, ca, identity, gate)
	if err != nil {
		log.Printf("egress: listen %s: %v", *addr, err)
		return 1
	}
	ceiling := "no request ceiling"
	if *perMinute > 0 {
		ceiling = fmt.Sprintf("%d requests/min per target", *perMinute)
	}

	log.Printf("egress proxy on %s; presenting %q; %s", proxy.Addr(), identity.UserAgent, ceiling)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := proxy.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "egress: %v\n", err)
		return 1
	}
	return 0
}
