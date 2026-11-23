package tool

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

type blockingExecSession struct {
	once   sync.Once
	killed chan struct{}
}

func (s *blockingExecSession) Read([]byte) (int, error)    { <-s.killed; return 0, io.EOF }
func (s *blockingExecSession) Write(p []byte) (int, error) { return len(p), nil }
func (s *blockingExecSession) Close() error                { s.Kill(); return nil }
func (s *blockingExecSession) Wait() error                 { <-s.killed; return nil }
func (s *blockingExecSession) ExitCode() int               { return -1 }
func (s *blockingExecSession) Kill()                       { s.once.Do(func() { close(s.killed) }) }

type blockingExecutor struct{ sess *blockingExecSession }

func (e blockingExecutor) RunOnce(context.Context, SpawnSpec) (ExecResult, error) {
	return ExecResult{}, nil
}

func (e blockingExecutor) Run(context.Context, SpawnSpec) (ExecSession, error) {
	return e.sess, nil
}

func TestExecutorTaskKillUsesSession(t *testing.T) {
	sess := &blockingExecSession{killed: make(chan struct{})}
	SetExecutor(blockingExecutor{sess: sess})
	t.Cleanup(func() { SetExecutor(nil) })
	m, err := NewManager(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, _, err := m.RunForeground(ctx, SpawnSpec{Command: "sleep 60", Kind: KindBash}, time.Minute)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("RunForeground error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled executor task did not stop")
	}
}
