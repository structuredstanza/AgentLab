package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// Every process a run starts belongs to a backend-issued netpolicy session. The
// supervisor enforces the packet and filesystem boundary from it, and the
// gateway judges each request against it. Sessions are minted here, from
// server-side rows only - the task, the conversation, and the purpose the
// calling subsystem runs - so no tool argument, prompt or spawned process can
// choose or widen one.
//
// A run whose session cannot be issued keeps running without one, and its tool
// processes refuse with the capability error instead of running unisolated. That
// is the fail-closed direction: the alternative would be an unconfined process.

// spawnPath is one place that can start a process inside a session.
type spawnPath struct {
	name string
	// caller is the subsystem asking, which fixes the purposes it may request.
	caller netpolicy.Caller
	// purpose is what this path runs as. It is a constant here, never a value
	// from a request.
	purpose netpolicy.Purpose
	// taskBound marks a path that only exists under an engagement task. The
	// issuer refuses a testing session without one; install is
	// operator/curator-initiated and is issued without a task.
	taskBound bool
}

// spawnPaths is every session shape the server issues. Install is atomic with
// this list: the entry point installs the execution client only when each path
// can actually be given a session, because one unwired path would turn every
// Bash call on it into a refusal.
var spawnPaths = []spawnPath{
	{"task engine", netpolicy.CallerAgent, netpolicy.PurposeTesting, true},
	{"chat", netpolicy.CallerChat, netpolicy.PurposeTesting, true},
	{"chat without a task", netpolicy.CallerChat, netpolicy.PurposeResearch, false},
	{"tool curator", netpolicy.CallerCurator, netpolicy.PurposeInstall, false},
	{"mcp discovery", netpolicy.CallerChat, netpolicy.PurposeResearch, false},
}

// probeSource answers a session issue without reading a task row: the assertion
// is about the wiring (caller, purpose and task binding), not about today's
// stored policy.
type probeSource struct{}

func (probeSource) PolicyState(context.Context, netpolicy.Session) (netpolicy.State, error) {
	return netpolicy.State{}, nil
}

// InstallExecutionBoundary installs the process-wide execution client, but only
// when every registered spawn path can be given a session. The check and the
// install are one step: installing with a path unwired would leave that path
// refusing every spawn, which is worse than not installing at all.
func InstallExecutionBoundary(src netpolicy.Source, c execbox.Client) error {
	return installBoundary(spawnPaths, src, c)
}

func installBoundary(paths []spawnPath, src netpolicy.Source, c execbox.Client) error {
	if c == nil {
		return errors.New("execbox: no client to install")
	}
	if src == nil {
		return errors.New("no policy source: no session could ever be issued")
	}
	issuer := netpolicy.NewIssuer(probeSource{})
	for _, p := range paths {
		var taskID int64
		if p.taskBound {
			taskID = 1
		}
		if _, err := issuer.Issue(context.Background(), p.caller, taskID, 1, p.purpose); err != nil {
			return fmt.Errorf("spawn path %q has no session: %w", p.name, err)
		}
	}
	execbox.Install(c)
	return nil
}

// session issues one session from the server's own state. It goes through the
// manager so the session is registered with the gateway and carries the
// credential its tool environment will present. The credential is revoked when
// ctx ends: a session that outlives its run is a leak, and the gateway's fixed
// cap turns a leak into a refusal for every later spawn.
func (s *Server) session(ctx context.Context, caller netpolicy.Caller, taskID, conversationID int64, purpose netpolicy.Purpose) (netpolicy.Session, error) {
	if s == nil || s.m == nil {
		return netpolicy.Session{}, errors.New("netpolicy: no policy source configured")
	}
	sess, err := s.m.IssueSession(ctx, caller, taskID, conversationID, purpose)
	if err != nil {
		return netpolicy.Session{}, err
	}
	context.AfterFunc(ctx, func() { s.m.RevokeSession(sess.Credential) })
	return sess, nil
}

// taskSessionContext attaches the session a task's tool processes run under.
//
// The task id comes from the engine's own state and the purpose is fixed to
// testing: a task run reaches the destinations its operator authorized, and
// nothing a model writes can change either. A task whose session cannot be
// issued keeps its context unchanged, so every spawn in it refuses. The
// credential is revoked when ctx ends, so a finished run leaves no live session
// behind.
func taskSessionContext(ctx context.Context, m *Manager, taskID string) context.Context {
	if m == nil || m.pg == nil {
		return ctx
	}
	tid, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || tid <= 0 {
		return ctx
	}
	sess, err := m.IssueSession(ctx, netpolicy.CallerAgent, tid, 0, netpolicy.PurposeTesting)
	if err != nil {
		log.Printf("[execbox] task %s runs without a session, so its tool processes will refuse: %v", taskID, err)
		return ctx
	}
	context.AfterFunc(ctx, func() { m.RevokeSession(sess.Credential) })
	return execbox.WithSession(ctx, sess)
}

// conversationSessionContext attaches the session a chat turn's tool processes
// run under. The purpose comes from the conversation row: the tool curator
// installs, a task-bound thread tests under that task, and a thread with no task
// is research. None of it is reachable from the message or a tool argument.
func (s *Server) conversationSessionContext(ctx context.Context, c *db.Conversation) context.Context {
	caller, purpose := netpolicy.CallerChat, netpolicy.PurposeResearch
	switch {
	case c.AgentKey == toolCuratorAgent:
		caller, purpose = netpolicy.CallerCurator, netpolicy.PurposeInstall
	case c.TaskID > 0:
		purpose = netpolicy.PurposeTesting
	}
	sess, err := s.session(ctx, caller, c.TaskID, c.ID, purpose)
	if err != nil {
		log.Printf("[execbox] conversation %d (%s) runs without a session, so its tool processes will refuse: %v", c.ID, c.AgentKey, err)
		return ctx
	}
	return execbox.WithSession(ctx, sess)
}

// discoverySessionContext attaches the unbound research session a backend MCP
// lookup runs under: no task, and no engagement target reachable. A stdio MCP
// server started without it refuses with the capability error.
func (s *Server) discoverySessionContext(ctx context.Context) context.Context {
	sess, err := s.session(ctx, netpolicy.CallerChat, 0, 0, netpolicy.PurposeResearch)
	if err != nil {
		log.Printf("[execbox] MCP discovery runs without a session, so a stdio server will refuse: %v", err)
		return ctx
	}
	return execbox.WithSession(ctx, sess)
}
