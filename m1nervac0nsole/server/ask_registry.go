package server

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// askLateAnswerTTL is how long an operator answer that arrived while no agent
// was waiting is kept. It is keyed by the question text, so an agent that asks
// the same question again collects it instead of making the human repeat it.
const askLateAnswerTTL = 30 * time.Minute

// pendingAsk is one operator question in flight for a task. A second
// ask_operator call for the same task joins it: same id, no second
// notification, and both callers wake on the same done channel.
type pendingAsk struct {
	id       string
	taskID   string
	question string
	done     chan struct{}
	answer   string
	answered bool
	waiters  int
}

type lateAnswer struct {
	askID string
	text  string
	at    time.Time
}

// askState is the in-memory ask protocol: at most one pending ask per task plus
// the answers that arrived after every waiter had stopped. It is process-local
// on purpose; the question itself is already in the task feed, so a restart
// loses only the join bookkeeping, not the hand-off.
type askState struct {
	mu     sync.Mutex
	byTask map[string]*pendingAsk
	late   map[string]lateAnswer
	seq    uint64
}

// join returns the task's pending ask, creating one when none is open. created
// is false for a join, which is what suppresses a second operator notification.
func (a *askState) join(taskID, question string) (ask *pendingAsk, created bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.byTask == nil {
		a.byTask = map[string]*pendingAsk{}
	}
	if ask = a.byTask[taskID]; ask != nil {
		return ask, false
	}
	a.seq++
	ask = &pendingAsk{
		id:       fmt.Sprintf("ask-%d", a.seq),
		taskID:   taskID,
		question: question,
		done:     make(chan struct{}),
	}
	a.byTask[taskID] = ask
	return ask, true
}

// wait blocks until the ask is answered or ctx ends. It reports whether the
// answer arrived; a timeout or a cancelled run leaves the ask pending.
func (a *askState) wait(ctx context.Context, ask *pendingAsk) (string, bool) {
	a.mu.Lock()
	ask.waiters++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		ask.waiters--
		a.mu.Unlock()
	}()
	select {
	case <-ask.done:
		a.mu.Lock()
		answer := ask.answer
		delete(a.late, lateAnswerKey(ask.taskID, ask.question))
		a.mu.Unlock()
		return answer, true
	case <-ctx.Done():
		// The answer may have landed in the same instant the wait ended. It is
		// still the reply to this question, so hand it over instead of leaving
		// a copy parked for a retry that may never come.
		a.mu.Lock()
		defer a.mu.Unlock()
		if ask.answered {
			delete(a.late, lateAnswerKey(ask.taskID, ask.question))
			return ask.answer, true
		}
		return "", false
	}
}

// answer resolves the task's pending ask with text. The answer is also parked
// for askLateAnswerTTL keyed by the question; a waiter that receives it deletes
// the parked copy, so only a reply that no agent collected survives for a retry.
func (a *askState) answer(taskID, text string) (askID string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ask := a.byTask[taskID]
	if ask == nil {
		return "", false
	}
	delete(a.byTask, taskID)
	ask.answer = text
	ask.answered = true
	if a.late == nil {
		a.late = map[string]lateAnswer{}
	}
	a.late[lateAnswerKey(taskID, ask.question)] = lateAnswer{askID: ask.id, text: text, at: time.Now()}
	close(ask.done)
	return ask.id, true
}

// takeLate returns and consumes a stored answer for this exact question.
func (a *askState) takeLate(taskID, question string) (askID, text string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := lateAnswerKey(taskID, question)
	entry, ok := a.late[key]
	if !ok {
		return "", "", false
	}
	delete(a.late, key)
	if time.Since(entry.at) > askLateAnswerTTL {
		return "", "", false
	}
	return entry.askID, entry.text, true
}

// pending reports the task's open ask, if any.
func (a *askState) pending(taskID string) *pendingAsk {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.byTask[taskID]
}

// drop removes ask from the task slot if it is still the registered one. It
// exists so a failed screenshot staging does not leave a phantom ask that a
// later call would join.
func (a *askState) drop(taskID string, ask *pendingAsk) {
	a.mu.Lock()
	if a.byTask[taskID] == ask {
		delete(a.byTask, taskID)
	}
	a.mu.Unlock()
}

func lateAnswerKey(taskID, question string) string {
	return taskID + "\x00" + question
}
