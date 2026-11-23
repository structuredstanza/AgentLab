package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// Error response text that goals_api.go returns to the user. Command and request field names (text, vulnclass, ...) are kept unchanged.
// gid) and enum values remain unchanged; human-readable messages are in English. English writeErr messages
// (task not found·invalid JSON·bad goal id) is within the F3b Chinese-only scope, so it is preserved.
const (
	errGoalTaskDeletingAdd    = "The task is being deleted, so no goal can be added"
	errGoalTaskDeletingEdit   = "Cannot modify the goal while the task is being deleted"
	errGoalTaskDeletingDelete = "The goal cannot be deleted because the task is being deleted"
	errGoalTextEmpty          = "The goal content cannot be empty"
	errGoalNotFound           = "Goal not found"
	errGoalReadAfterAdd       = "Failed to read back the goal after saving it"
	errGoalReadAfterEdit      = "Failed to read the goal after updating it"
)

// Manual CRUD endpoints for the overview "Goal Management" feature. They write to the same batch of goal nodes as the set_goals tool on the agent side,
// but the entry point is a human adding, editing, and deleting directly in the UI. After an add or edit, reuse the "revive task" logic (admitTask resume:
// terminal state→running, clear pause, enqueue if necessary). Deletion does not revive (per product decision). Every mutating handler goes through
// beginTaskOperation/decInflight to avoid racing with task deletion (consistent with intent CRUD).

// listGoals returns all goals for this task (text/vulnclass/state already split out), for rendering the goal management card.
func (s *Server) listGoals(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	goals, err := t.Store.ListByKind(db.KindGoal, 10000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"goals": goalDTOs(goals)})
}

// addGoal manually adds one goal: persist it (attached under the task root spawns) → record an "added goal" trigger that wakes the task
// planner → revive the task so the planner re-evaluates whether it is achieved under the new goal.
func (s *Server) addGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingAdd)
		return
	}
	defer s.engine.decInflight(t.ID)

	var body struct {
		Text      string `json:"text"`
		VulnClass string `json:"vulnclass"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, errGoalTextEmpty)
		return
	}
	payload := map[string]any{"text": text}
	if vc := strings.TrimSpace(body.VulnClass); vc != "" {
		payload["vulnclass"] = vc
	}
	id, err := t.Store.AddGoal(payload, "human")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if of, _ := t.Store.OriginFactID(); of > 0 && id > 0 {
		_ = t.Store.Link(of, db.RelSpawns, id) // goal descends from the task root (origin fact)
	}
	t.NotifyGoal([]string{text})     // Record "the human added a new goal: …", which triggers and wakes the planner
	ack, admitErr := s.reviveTask(t) // Move a completed or paused task back to the running state so it continues to run
	node, _ := t.Store.GetNode(id)
	if node == nil {
		writeErr(w, 500, errGoalReadAfterAdd)
		return
	}
	writeJSON(w, 200, goalWithAdmission(node, ack, admitErr))
}

// editGoal manually modifies a goal's text (and vulnclass): update the database → record "the user changed the goal from old to new"
// Trigger and wake the planner → revive the task so the planner adjusts direction under the new goal.
func (s *Server) editGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingEdit)
		return
	}
	defer s.engine.decInflight(t.ID)

	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "bad goal id")
		return
	}
	var body struct {
		Text      string `json:"text"`
		VulnClass string `json:"vulnclass"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, errGoalTextEmpty)
		return
	}
	node, err := t.Store.GetNode(gid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindGoal {
		writeErr(w, 404, errGoalNotFound)
		return
	}
	oldText := goalDTO(node).Text
	if err := t.Store.UpdateGoalPayload(gid, text, strings.TrimSpace(body.VulnClass)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.NotifyGoalEdited(oldText, text) // Record "the human changed the goal from old to new", which triggers and wakes the planner
	ack, admitErr := s.reviveTask(t)  // Same as addition: revive the task to re-evaluate under the new goal
	updated, _ := t.Store.GetNode(gid)
	if updated == nil {
		writeErr(w, 500, errGoalReadAfterEdit)
		return
	}
	writeJSON(w, 200, goalWithAdmission(updated, ack, admitErr))
}

// goalAdmissionDTO is the goal plus what admission did. The goal is persisted
// before admission, so a failed admission is reported here, not as a failed save.
type goalAdmissionDTO struct {
	GoalDTO
	Admission      string `json:"admission,omitempty"`
	AdmissionError string `json:"admission_error,omitempty"`
}

func goalWithAdmission(n *db.Node, ack string, err error) goalAdmissionDTO {
	out := goalAdmissionDTO{GoalDTO: goalDTO(n), Admission: ack}
	if err != nil {
		out.AdmissionError = err.Error()
	}
	return out
}

// deleteGoal manually deletes a goal (hard delete, cascading to edges/anchors): delete from the database → record "the user deleted the goal X"
// Trigger a wake-up so the planner re-evaluates the remaining goals accordingly. Per the product decision, deleting does NOT revive the task.
func (s *Server) deleteGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingDelete)
		return
	}
	defer s.engine.decInflight(t.ID)

	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "bad goal id")
		return
	}
	node, err := t.Store.GetNode(gid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindGoal {
		writeErr(w, 404, errGoalNotFound)
		return
	}
	text := goalDTO(node).Text
	if err := t.Store.DeleteGoal(gid); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.NotifyGoalDeleted(text) // Record "the user deleted this goal: …", then trigger and wake the planner (does not revive the task)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
