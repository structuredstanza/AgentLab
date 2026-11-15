package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
)

// runExecbox dispatches the execution-boundary subcommands. The supervisor is a
// separate privileged process so tool processes never share a process, a
// namespace or an address space with the backend, and so its socket can be
// hidden from every session.
func runExecbox(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: m1nervac0nsole execbox <serve|probe|bridge> [flags]")
		return 2
	}
	switch args[0] {
	case "serve":
		return runExecboxServe(args[1:])
	case "probe":
		return runExecboxProbe(args[1:])
	case "bridge":
		return runExecboxBridge(args[1:])
	case execbox.ChildMode:
		return execbox.RunChild(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "execbox: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runExecboxServe(args []string) int {
	fs := flag.NewFlagSet("execbox serve", flag.ContinueOnError)
	socket := fs.String("socket", execbox.SocketPath(), "Unix socket the client connects to")
	gateway := fs.String("gateway", "", "gateway host:port a session may reach (default 127.0.0.1:8788)")
	resolver := fs.String("resolver", "", "upstream resolver host:port (default: first nameserver in /etc/resolv.conf)")
	workspace := fs.String("workspace", "", "comma-separated writable workspace roots")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := execbox.DefaultConfig()
	cfg.Socket = *socket
	if *gateway != "" {
		cfg.Gateway = *gateway
	}
	if *resolver != "" {
		cfg.Resolver = *resolver
	}
	if *workspace != "" {
		cfg.WritableRoots = strings.Split(*workspace, ",")
	}
	cfg.Logf = func(format string, a ...any) { log.Printf(format, a...) }
	sup, err := execbox.NewSupervisor(cfg)
	if err != nil {
		log.Printf("[execbox] refusing to serve: %v", err)
		return 3
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := sup.Serve(ctx); err != nil {
		log.Printf("[execbox] serve: %v", err)
		return 1
	}
	_ = sup.Close()
	return 0
}

func runExecboxProbe(args []string) int {
	fs := flag.NewFlagSet("execbox probe", flag.ContinueOnError)
	gateway := fs.String("gateway", "", "gateway host:port to verify")
	workspace := fs.String("workspace", "", "comma-separated writable workspace roots the supervisor will use")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := execbox.DefaultConfig()
	if *gateway != "" {
		cfg.Gateway = *gateway
	}
	if *workspace != "" {
		cfg.WritableRoots = strings.Split(*workspace, ",")
	}
	rep := execbox.Probe(cfg)
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(out))
	if !rep.OK() {
		return 1
	}
	return 0
}

// The bridge subcommand runs a program inside a session for a caller that can
// only spawn a process. See execbox.BridgeCommand.
func runExecboxBridge(args []string) int {
	argv := args
	for i, a := range args {
		if a == "--" {
			argv = args[i+1:]
			break
		}
	}
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "execbox bridge: no program")
		return 2
	}
	sess, err := execbox.BridgeSession()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	env, err := execbox.BridgeProgramEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	client := execbox.NewClient("")
	rwc, err := client.Run(context.Background(), sess, execbox.Spec{
		Argv: argv,
		// /tmp is the session's own tmpfs, so the program's scratch files never
		// reach the backend and are gone with the session.
		Dir: "/tmp",
		Env: env,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "execbox bridge: %v\n", err)
		return 3
	}
	proc, ok := execbox.ProcessOf(rwc)
	if !ok {
		fmt.Fprintln(os.Stderr, "execbox bridge: session has no process control")
		return 3
	}
	// stdin EOF ends the program's input without ending the session, so a
	// program that reads stdin to EOF finishes and reports its own exit code.
	go func() {
		_, _ = io.Copy(proc, os.Stdin)
		_ = proc.CloseStdin()
	}()
	// stderr is drained to EOF before the code is reported, so the last thing
	// the program wrote before exiting is not lost with the session.
	drained := make(chan struct{})
	if stderr := proc.Stderr(); stderr != nil {
		go func() {
			defer close(drained)
			_, _ = io.Copy(os.Stderr, stderr)
		}()
	} else {
		close(drained)
	}
	_, _ = io.Copy(os.Stdout, proc)
	<-drained
	code, _ := proc.Wait()
	_ = proc.Close()
	return code
}
