// Command m1nervac0nsole runs the m1nervac0nsole backend: the dual SQLite graph stores,
// the event-driven exploration engine, and the JSON HTTP API consumed by the
// shadcn/ui frontend.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/config"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/server"
)

// version is the build version, injected at release time via
// -ldflags "-X main.version=<tag>". Defaults to "dev" for local builds.
var version = "dev"

// printBanner writes the startup banner + version/runtime info to stdout.
func printBanner(addr string) {
	fmt.Println("  m1nervac0nsole")
	fmt.Println("  AI Autonomous Penetration Testing System")
	fmt.Printf("  Version %s  ·  %s/%s  ·  %s  ·  Listening on %s\n\n",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), addr)
}

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) > 1 && os.Args[1] == "execbox" {
		return runExecbox(os.Args[2:])
	}
	var (
		addr    = flag.String("addr", "127.0.0.1:8787", "HTTP listen address (default accepts local connections only; use :8787 to serve other hosts)")
		dataDir = flag.String("data", filepath.Join(config.BaseDir(), "data"), "data directory for SQLite stores (default: data/ next to the executable)")
		proxy   = flag.String("proxy", "127.0.0.1:8788", "traffic recording proxy address (empty to disable)")
	)
	flag.Parse()

	// hand the build version to the server package so GET /api/health can report it
	// to the frontend top bar.
	server.BuildVersion = version

	printBanner(*addr)

	// capture backend logs into the in-memory sink (still to stderr) so the /logs
	// page can show a live log stream. Do this first, to catch startup logs too.
	server.StartLogCapture()

	// surface which config file the binary reads (absolute, so `go run`'s relative
	// "config.json" — resolved against the CWD — is unambiguous).
	cfgPath := config.Path()
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if _, e := os.Stat(cfgPath); e == nil {
		log.Printf("[config] Configuration file: %s", cfgPath)
	} else {
		log.Printf("[config] Configuration file: %s (file not found · only the M1NERVAC0NSOLE_PG_DSN environment variable is used)", cfgPath)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, shutdown := shutdownContext(sigCtx)
	defer shutdown(agent.AbortShutdown)

	mgr, err := server.NewManager(*dataDir, *proxy)
	if err != nil {
		log.Fatalf("open stores: %v", err)
	}
	defer mgr.Close()

	// Install the unprivileged execution boundary once, before any run can start.
	// Every tool process is started by the supervisor inside a session; a host
	// without the client refuses instead of spawning unisolated. The install is
	// atomic with the session wiring: one unwired spawn path would turn every
	// Bash call on it into a refusal, so the wiring is asserted first and nothing
	// is installed when it fails.
	execClient := execbox.NewClient("")
	if err := server.InstallExecutionBoundary(mgr.PG(), execClient); err != nil {
		log.Printf("[execbox] execution boundary NOT installed: %v", err)
	} else if rep, err := execClient.Capabilities(ctx); err != nil {
		log.Printf("[execbox] capability probe failed: %v", err)
	} else {
		log.Printf("[execbox] %s", rep.String())
	}

	skillDir := config.SkillDir()
	if abs, err := filepath.Abs(skillDir); err == nil {
		skillDir = abs
	}
	log.Printf("[config] Skill directory: %s", skillDir)
	srv := server.New(ctx, mgr, skillDir, *dataDir, config.BaseDir())
	srv.WarnIfExposed(*addr)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout bounds the whole request (headers plus body), so a client
		// that dribbles one byte every 30s cannot pin a goroutine forever. It is
		// generous because the workspace upload path accepts up to 512 MiB: five
		// minutes still allows ~1.7 MB/s and cuts a stalled body long before it
		// matters. IdleTimeout closes keep-alive connections that go quiet.
		//
		// WriteTimeout is deliberately left unset: SSE and the download handlers
		// hold a response open for as long as the client wants it, and a
		// blanket deadline would cut those streams. The consequence is honest
		// and should be known: a client that stops reading holds its handler
		// goroutine until the connection breaks, so anything fronting this
		// server (the reverse proxy in dev.sh, a load balancer in a deployment)
		// must bound idle responses. Streaming handlers cannot set a per-write
		// deadline themselves here — http.ResponseController applies to the
		// connection this process owns, and the SSE writers flush through the
		// same ResponseWriter, so a single deadline would cap the whole stream.
		ReadTimeout:    5 * time.Minute,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		log.Printf("m1nervac0nsole %s backend listening on %s (data=%s, workers=%d)", version, *addr, *dataDir, mgr.Workers())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return 0
}

// shutdownContext deliberately does not derive from signalCtx. If it did, the
// parent's plain context.Canceled could win the race before AbortShutdown was
// attached to the child, losing the diagnostic cause in every running Agent.
func shutdownContext(signalCtx context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, shutdown := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-signalCtx.Done():
			shutdown(agent.AbortShutdown)
		case <-ctx.Done():
		}
	}()
	return ctx, shutdown
}
