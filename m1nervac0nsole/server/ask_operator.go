package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	actool "github.com/structuredstanza/norma/tool"
)

const askOperatorMaxImage = 10 << 20

var askOperatorImageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".webp": true, ".gif": true}

// toolAskOperator lets a worker formally request operator input and pauses the intent.
func (s *Server) toolAskOperator() actool.CoreTool {
	return wrTool("ask_operator",
		"Ask the human operator for input you cannot obtain yourself (a captcha solution, an email/SMS OTP code, a 2FA answer, a decision, or an action only they can perform). The question appears in this intent's chat for the operator, optionally with a screenshot, and this intent then pauses; the operator's reply resumes this run with the answer as your next input. Ask precisely, and only when you are genuinely blocked. When the block is environmental (a sandboxed or filtered network path, a missing binary or key, a proxy or TLS failure this runtime cannot fix), do not retry or work around it: include in the question the exact single command the operator should run in their own terminal, as one copy-pastable line, plus what to paste back, then wait.",
		map[string]any{"type": "object", "properties": map[string]any{
			"question":   map[string]any{"type": "string", "description": "What you need from the operator, precisely. For environmental blocks: the exact single command they should run in their own terminal (one line, copy-pastable) and what to paste back."},
			"image_path": map[string]any{"type": "string", "description": "Optional path to a screenshot (png/jpg/jpeg/webp/gif, max 10MB)."},
		}, "required": []any{"question"}},
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var req struct {
				Question  string `json:"question"`
				ImagePath string `json:"image_path"`
			}
			_ = json.Unmarshal(in, &req)
			q := strings.TrimSpace(req.Question)
			q = s.redactProviderCredentials(q)
			if q == "" {
				return actool.Errorf("Error: question is required"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID == 0 || ri.IntentID == 0 {
				return actool.Errorf("Error: ask_operator can only be used inside a worker intent run"), nil
			}
			taskID := fmt.Sprintf("%d", ri.TaskID)
			t := s.m.ResolveTask(taskID)
			if t == nil {
				return actool.Errorf("Error: task not found"), nil
			}
			att, err := stageAskOperatorImage(s.m.dir, taskID, req.ImagePath)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			text, att := handoffText(q, att, s.hasProviderCredentials())
			act := userActivityWithAttachments("worker", text, att)
			node := ri.IntentID
			act.NodeID = &node
			s.engine.emitActivity(t, act)
			if _, err := s.applyIntentControl(context.Background(), t, ri.IntentID, "pause", firstLine(q, 120), ""); err != nil {
				return actool.Errorf("Error: question delivered but pausing the intent failed: " + err.Error()), nil
			}
			return actool.Text("Question delivered to the operator. This intent is pausing now: finish your current step, record everything you already know as facts, and stop. The operator's reply will resume this run and arrive as your next input."), nil
		})
}

// toolReportBlocked lets the planner stop an engagement that cannot continue
// without a human and name the exact action that would unblock it. It exists so
// the planner has a correct move other than dispatching yet another intent
// against a target that is absent, filtered, or missing a credential.
func (s *Server) toolReportBlocked() actool.CoreTool {
	return wrTool("report_blocked",
		"Stop this task because the engagement cannot continue without a human: the target is unreachable (host down, port filtered at the network layer, the address moved and the new one is unknown), a credential or tool is missing, or the network path is blocked in a way this runtime cannot fix. Do not dispatch another intent that would only re-check availability. The task moves to needs_operator with your reason, its planner and workers stop, and the operator sees the exact action they must take; resuming the task lets planning continue.",
		objSchema(map[string]any{
			"reason":          strParam("Why the engagement cannot continue, concretely: what was tried, what came back, and why no intent can advance it."),
			"operator_action": strParam("The exact single command or decision the human should take (one line, copy-pastable), and what to report back."),
		}, "reason", "operator_action"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Reason         string `json:"reason"`
				OperatorAction string `json:"operator_action"`
			}
			_ = json.Unmarshal(in, &a)
			reason := s.redactProviderCredentials(strings.TrimSpace(a.Reason))
			action := s.redactProviderCredentials(strings.TrimSpace(a.OperatorAction))
			if reason == "" || action == "" {
				return actool.Errorf("Error: reason and operator_action are both required"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID == 0 {
				return actool.Errorf("Error: report_blocked can only be used inside a task run"), nil
			}
			taskID := fmt.Sprintf("%d", ri.TaskID)
			t := s.m.ResolveTask(taskID)
			if t == nil {
				return actool.Errorf("Error: task not found"), nil
			}
			n, err := strconv.ParseInt(taskID, 10, 64)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			// Stop the loops exactly like a task pause, BEFORE the block is
			// persisted: needs_operator is not terminal, so a crash between the
			// two writes must leave an ordinary paused task (resumable) rather
			// than a blocked status the resume path would refuse.
			if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortBlockedOnOperator); err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			if err := s.m.PG().SetNeedsOperator(n, reason); err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			// The reason lives in PostgreSQL; the live handle carries status only,
			// so mirror the status here for the loops' needs_operator gate.
			if err := s.m.SetTaskStatus(taskID, db.StatusNeedsOperator); err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			// Same activity shape ask_operator uses for its question: a user-kind
			// row so the operator sees the handoff in the task feed.
			s.engine.emitActivity(t, userActivityWithAttachments("planner",
				"OPERATOR ACTION REQUIRED: "+reason+" (do this: "+action+")", nil))
			return actool.Text("Block reported: this task is now needs_operator and this run is stopping. Do not dispatch further intents; the operator must act before planning resumes."), nil
		})
}

// hasProviderCredentials fails closed for screenshots: images cannot be reliably
// inspected for secrets before they are attached to an operator handoff.
func (s *Server) hasProviderCredentials() bool {
	if s == nil || s.m == nil || s.m.pg == nil {
		return false
	}
	profiles, err := s.m.pg.ListProfiles()
	if err != nil {
		return true
	}
	for _, profile := range profiles {
		if profile != nil && profile.APIKey != "" {
			return true
		}
	}
	return false
}

func (s *Server) redactProviderCredentials(text string) string {
	if s == nil || s.m == nil || s.m.pg == nil {
		return text
	}
	profiles, err := s.m.pg.ListProfiles()
	if err != nil {
		return "[handoff text withheld: provider credentials could not be checked]"
	}
	for _, profile := range profiles {
		if profile != nil && profile.APIKey != "" {
			text = strings.ReplaceAll(text, profile.APIKey, "[REDACTED PROVIDER CREDENTIAL]")
		}
	}
	return text
}

// handoffText composes the operator-facing text for a hand-off and decides
// whether the staged screenshot rides along as an attachment.
//
// An image cannot be redacted the way the question text is
// (redactProviderCredentials replaces the configured API keys in text only), so
// with provider credentials configured the screenshot is named by path and left
// out of the conversation: the operator opens the staged file in the task
// workspace. The picture still reaches the human, which is the point of a
// handoff.
func handoffText(question string, att []chatAttachment, imagesWithheld bool) (string, []chatAttachment) {
	text := "OPERATOR INPUT REQUESTED: " + question
	if len(att) > 0 && imagesWithheld {
		text += " (screenshot saved at " + att[0].Path + " - open it in the task workspace)"
		att = nil
	}
	return text + " (this intent is pausing; reply here to resume it with your answer)", att
}

func stageAskOperatorImage(dataDir, taskID, src string) ([]chatAttachment, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, nil
	}
	ext := strings.ToLower(filepath.Ext(src))
	if !askOperatorImageExt[ext] {
		return nil, fmt.Errorf("image_path must be a png/jpg/jpeg/webp/gif file, got %q", filepath.Base(src))
	}
	st, err := os.Stat(src)
	if err != nil {
		return nil, fmt.Errorf("image not readable: %v", err)
	}
	if st.Size() > askOperatorMaxImage {
		return nil, fmt.Errorf("image too large (%s, max 10MB)", humanBytes(st.Size()))
	}
	dir := filepath.Join(dataDir, "tasks", taskID, "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("ask-operator-%d%s", time.Now().Unix(), ext)
	in, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	out, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return nil, err
	}
	return []chatAttachment{{Name: name, Path: "uploads/" + name, Size: st.Size()}}, nil
}
