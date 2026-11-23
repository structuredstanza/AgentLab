package server

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
)

// Admission outcomes must be real lifecycle changes the caller can rely on: a
// full concurrency limit parks the task (queued, not running) and a stale handle
// whose persisted status moved on is rejected rather than silently revived.
func TestReviveTaskReportsQueuedAndPropagatesRejection(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	defer restoreConcurrencySetting(t, m)()
	if err := m.SetConcurrency(true, 1); err != nil {
		t.Fatal(err)
	}
	holder, err := m.CreateTask("slot holder", "hold", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTask("follow-up", "must wait", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = m.DeleteTask(holder.ID, DeleteTaskOptions{})
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
	}()
	if err := m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}

	s := newAdmissionTestServer(m, nil)
	ack, err := s.reviveTask(task)
	if err != nil {
		t.Fatal(err)
	}
	if !task.Queued || ack == "" {
		t.Fatalf("limit full: task must be queued with an ack, queued=%v ack=%q", task.Queued, ack)
	}

	// Stale handle: the database moved to done after the handle was read.
	stale, err := m.CreateTask("stale", "terminal writer wins", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(stale.ID, DeleteTaskOptions{}) }()
	id, _ := strconv.ParseInt(stale.ID, 10, 64)
	if err := m.pg.SetStatus(id, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reviveTask(stale); err == nil {
		t.Fatal("admission rejected by a concurrent terminal transition must reach the caller as an error")
	}
}

type sleepProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func startSleepProcess(t *testing.T) *sleepProc {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	p := &sleepProc{cmd: cmd, done: make(chan struct{})}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() { _ = cmd.Wait(); close(p.done) }()
	return p
}

func (p *sleepProc) killAndWait() { _ = p.cmd.Process.Kill(); <-p.done }

func (p *sleepProc) alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// kill_work through the real ToolSet and Engine: it must not return success until
// the worker finished its cleanup (a stand-in for Session.Close killing background
// processes) and the intent is recorded stopped.
func TestKillWorkToolWaitsForWorkerCleanup(t *testing.T) {
	_, s, task := newHintTestServer(t)
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "running"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := task.Store.CompareAndSetIntentState(intentID, "open", "running"); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)

	proc := startSleepProcess(t)
	s.engine.registerWork(intentID, func(error) {
		go func() {
			time.Sleep(100 * time.Millisecond) // slow cleanup the caller must wait for
			proc.killAndWait()
			_ = s.engine.setIntentState(task, intentID, "running", "stopped")
			_, complete := s.engine.detachWork(intentID)
			complete(nil)
		}()
	})

	tools := agent.NewToolSet(task.Store, "human")
	tools.SetTaskID(taskID)
	tools.SetKillWork(s.engine.killWorkByOperator)
	input, _ := json.Marshal(map[string]any{"intent_id": intentID, "reason": "operator stop"})
	for _, tool := range tools.MainAgentTools() {
		if tool.Name() != "kill_work" {
			continue
		}
		res, err := tool.Call(context.Background(), input, nil)
		if err != nil || res.IsError {
			t.Fatalf("kill_work: err=%v result=%s", err, res.Flatten())
		}
		if proc.alive() {
			t.Fatal("kill_work returned while the background process was still alive")
		}
		node, _ := task.Store.GetNode(intentID)
		if node == nil || node.State != "stopped" {
			t.Fatalf("intent after kill_work = %+v, want stopped", node)
		}
		return
	}
	t.Fatal("main agent exposes no kill_work tool")
}

// A worker that never settles must not be reported as stopped.
func TestKillWorkWithinRejectsUnsettledWorker(t *testing.T) {
	e := NewEngine(nil)
	e.registerWork(7, func(error) {})
	if err := e.killWorkWithin(context.Background(), 0, 7, "stuck", agent.AbortKilledByPlanner, 30*time.Millisecond); err == nil {
		t.Fatal("an unsettled worker must not yield a successful stop")
	}
}

func TestSeedMainAgentKillWorkBinding(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	const flag = "mainagent_kill_work_v1"
	var agents string
	if err := m.pg.QueryRow(`SELECT agents::text FROM tools WHERE key='kill_work'`).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	prior, found, err := m.pg.GetSetting(flag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`UPDATE tools SET agents=$1::jsonb WHERE key='kill_work'`, agents)
		if found {
			_ = m.pg.SetSetting(flag, prior)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, flag)
		}
	})
	if _, err := m.pg.Exec(`DELETE FROM settings WHERE key=$1`, flag); err != nil {
		t.Fatal(err)
	}
	for _, wantBound := range []bool{true, false} {
		if err := m.pg.RemoveAgentFromTool("mainagent", "kill_work"); err != nil {
			t.Fatal(err)
		}
		s.seedMainAgentKillWorkBinding()
		var bound bool
		err := m.pg.QueryRow(`SELECT agents ? 'mainagent' FROM tools WHERE key='kill_work'`).Scan(&bound)
		if err != nil || bound != wantBound {
			t.Fatalf("kill_work bound to mainagent = %t, err=%v, want %t", bound, err, wantBound)
		}
	}
}
