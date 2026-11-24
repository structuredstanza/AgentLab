package server

import (
	"context"
	"testing"
)

// newFixtureServer starts a Server on m. At cleanup it cancels the server
// context and drains it. Register m.Close and any DB-deleting cleanups with
// t.Cleanup BEFORE calling this: Cleanups run LIFO, so the drain runs first,
// then the deletes, then Close, then TempDir removal. Deferred calls run before
// all Cleanups and must not be used for these.
func newFixtureServer(t *testing.T, m *Manager) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() {
		cancel()
		drainFixtureServer(s, m)
	})
	return s
}

// drainFixtureServer joins every background owner that New may have started for
// shared-PG tasks: task runtimes (restored by New for non-terminal tasks), the
// archive worker, and the side-question publisher. Call it from a Cleanup
// registered after m.Close, so it runs before the DB closes.
func drainFixtureServer(s *Server, m *Manager) {
	for _, task := range m.List() {
		s.engine.StopTask(task.ID)
	}
	s.archiveWG.Wait()
	s.remediationWG.Wait()
	if s.side != nil {
		<-s.side.done
	}
}
