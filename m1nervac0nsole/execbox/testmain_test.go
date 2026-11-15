package execbox

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

// TestMain dispatches the two modes the supervisor re-executes this binary in:
// the session child, and a standalone supervisor for the crash test. A test
// binary stands in for the product binary because the supervisor starts
// os.Executable().
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "execbox" {
		switch os.Args[2] {
		case ChildMode:
			os.Exit(RunChild(os.Args[3:]))
		case "serve-test":
			os.Exit(runTestSupervisor())
		}
	}
	os.Exit(m.Run())
}

// runTestSupervisor serves with the configuration the crash test passes in the
// environment, so the test can SIGKILL a real supervisor process.
func runTestSupervisor() int {
	cfg := DefaultConfig()
	cfg.Socket = os.Getenv("EXECBOX_TEST_SOCKET")
	cfg.StateDir = os.Getenv("EXECBOX_TEST_STATE")
	cfg.CgroupRoot = os.Getenv("EXECBOX_TEST_CGROUP")
	cfg.Gateway = os.Getenv("EXECBOX_TEST_GATEWAY")
	cfg.Resolver = os.Getenv("EXECBOX_TEST_RESOLVER")
	cfg.WritableRoots = []string{os.Getenv("EXECBOX_TEST_WORKSPACE")}
	cfg.ToolboxRoot = os.Getenv("EXECBOX_TEST_TOOLBOX")
	cfg.Logf = func(format string, a ...any) { log.Printf(format, a...) }
	sup, err := NewSupervisor(cfg)
	if err != nil {
		log.Printf("[execbox-test] refusing to serve: %v", err)
		return 3
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := sup.Serve(ctx); err != nil {
		log.Printf("[execbox-test] serve: %v", err)
		return 1
	}
	return 0
}
