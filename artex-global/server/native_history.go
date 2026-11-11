package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strconv"
	"time"

	"github.com/structuredstanza/AgentLab/artex-global/agent"
	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/intercept"
	"github.com/structuredstanza/AgentLab/artex-global/llmrec"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/transcript"
)

type nativeHistoryStep struct {
	SessionID    string                      `json:"session_id"`
	Source       agent.NativeHistorySource   `json:"source"`
	Target       agent.NativeHistoryIdentity `json:"target"`
	PrefixCount  int                         `json:"prefix_count"`
	PrefixSHA256 string                      `json:"prefix_sha256"`
}

type nativeHistoryRecord struct {
	Version      int                         `json:"version"`
	Record       string                      `json:"record"`
	SessionID    string                      `json:"session_id"`
	Identity     agent.NativeHistoryIdentity `json:"identity"`
	ThinkingType string                      `json:"thinking_type,omitempty"`
	Steps        []nativeHistoryStep         `json:"steps,omitempty"`
}

type nativeHistoryProvider struct {
	inner        llm.Provider
	s            *Server
	identity     agent.NativeHistoryIdentity
	thinkingType string
	native       bool
}

func (s *Server) withNativeHistory(p llm.Provider, id int64, cfg agent.Config) llm.Provider {
	provider := cfg.Provider()
	native := cfg.AuthMethod != "" && cfg.AuthMethod != "api_key"
	if native {
		provider = cfg.NativeProviderName()
	}
	return &nativeHistoryProvider{inner: p, s: s, identity: agent.NativeHistoryIdentity{ProfileID: strconv.FormatInt(id, 10), Provider: provider, Model: cfg.Model, ReasoningEffort: cfg.ReasoningEffort}, thinkingType: cfg.ThinkingType, native: native}
}

func (p *nativeHistoryProvider) RequiresComplete() bool { return llm.RequiresComplete(p.inner) }
func (p *nativeHistoryProvider) PrepareModelCall(ctx context.Context, req llm.CompletionRequest, mode bool) (context.Context, bool, error) {
	return llm.PrepareModelCall(ctx, p.inner, req, mode)
}
func (p *nativeHistoryProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	ctx, req, err := p.prepare(ctx, req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	return p.inner.Complete(ctx, req)
}
func (p *nativeHistoryProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		ctx, req, err := p.prepare(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		for event, err := range p.inner.Stream(ctx, req) {
			if !yield(event, err) {
				return
			}
		}
	}
}

type nativeHistoryScope struct {
	task           *Task
	conversationID int64
}

func (s *Server) nativeScope(ctx context.Context) nativeHistoryScope {
	if taskID := llmrec.TaskIDFrom(ctx); taskID != "" {
		s.m.mu.RLock()
		task := s.m.tasks[taskID]
		s.m.mu.RUnlock()
		return nativeHistoryScope{task: task}
	}
	return nativeHistoryScope{conversationID: intercept.ConvIDFromContext(ctx)}
}
func (scope nativeHistoryScope) valid() bool { return scope.task != nil || scope.conversationID > 0 }
func (scope nativeHistoryScope) explorationID() int64 {
	if scope.task != nil {
		return scope.task.ExpID
	}
	return 0
}

func (s *Server) appendNativeHistory(ctx context.Context, scope nativeHistoryScope, record nativeHistoryRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	a := db.Activity{Kind: "llm_native", Worker: "system", Summary: "Native model routing " + record.Record, Metadata: raw, CreatedAt: time.Now()}
	if scope.task != nil {
		id, err := s.engine.appendActivity(scope.task, a)
		if err != nil {
			return err
		}
		a.ID = id
		s.engine.bc.Publish(scope.task.ID, a)
		s.engine.touch(scope.task.ID)
		return nil
	}
	// Conversations store structured activity detail rather than task metadata.
	a.Detail = string(raw)
	_, err = s.m.pg.AppendConvActivity(scope.conversationID, a)
	return err
}

func nativeHistoryError(reason string) error {
	return fmt.Errorf("%w: %s", llm.ErrHistoryRejected, reason)
}
func sameNativeDestination(a, b agent.NativeHistoryIdentity) bool { return a == b }
func sourceChoice(identity agent.NativeHistoryIdentity) agent.NativeModelChoice {
	return agent.NativeModelChoice{Model: identity.Model, ReasoningEffort: identity.ReasoningEffort}
}

func (p *nativeHistoryProvider) prepare(ctx context.Context, req llm.CompletionRequest) (context.Context, llm.CompletionRequest, error) {
	sessionID := transcript.SessionIDFrom(ctx)
	_, _, foreign, err := agent.NativeHistoryBoundary(req, sessionID, p.identity)
	if p.native && sessionID == "" {
		return ctx, req, nativeHistoryError("missing native session identity")
	}
	if err != nil {
		return ctx, req, err
	}
	if !foreign && !p.native {
		return ctx, req, nil
	}
	scope := p.s.nativeScope(ctx)
	if !scope.valid() {
		if foreign {
			return ctx, req, nativeHistoryError("no owning task or conversation")
		}
		return ctx, req, nil
	}
	selection := nativeHistoryRecord{Version: 1, Record: "selection", SessionID: sessionID, Identity: p.identity, ThinkingType: p.thinkingType}
	if req.Thinking != "" {
		selection.ThinkingType = req.Thinking
	}
	if foreign {
		ctx, req, err = p.handoff(ctx, req, scope, selection)
		if err != nil {
			return ctx, req, err
		}
	}
	// Actual immutable provider selection, not a foreign envelope, is authority.
	// Persist before dispatch so recording-off and process resume remain safe.
	// Only a change of selection is a new fact: handoff reads the set of distinct
	// selections, so repeating one on every model call only floods the activity log.
	key := fmt.Sprintf("%d/%d/%s", scope.explorationID(), scope.conversationID, sessionID)
	fingerprint := fmt.Sprintf("%v|%s", selection.Identity, selection.ThinkingType)
	if last, _ := p.s.nativeSelected.Load(key); last != fingerprint {
		if err := p.s.appendNativeHistory(ctx, scope, selection); err != nil {
			return ctx, req, nativeHistoryError("cannot persist selected provider")
		}
		p.s.nativeSelected.Store(key, fingerprint)
	}
	if err := ctx.Err(); err != nil {
		return ctx, req, err
	}
	return ctx, req, nil
}

func (p *nativeHistoryProvider) handoff(ctx context.Context, original llm.CompletionRequest, scope nativeHistoryScope, selection nativeHistoryRecord) (context.Context, llm.CompletionRequest, error) {
	sessionID := selection.SessionID
	raws, err := p.s.m.pg.NativeHistoryMetadata(ctx, scope.explorationID(), scope.conversationID, sessionID)
	if err != nil {
		return ctx, original, nativeHistoryError("cannot read routing authority")
	}
	var owners []nativeHistoryRecord
	var steps []nativeHistoryStep
	for _, raw := range raws {
		var record nativeHistoryRecord
		if json.Unmarshal(raw, &record) != nil || record.Version != 1 || record.SessionID != sessionID {
			return ctx, original, nativeHistoryError("invalid persisted routing authority")
		}
		switch record.Record {
		case "selection":
			owners = append(owners, record)
		case "handoff":
			steps = record.Steps
		default:
			return ctx, original, nativeHistoryError("unknown persisted routing authority")
		}
	}
	owners = append(owners, selection)
	working := original
	for _, step := range steps {
		digest, err := agent.NativeHistoryPrefixDigest(original, step.PrefixCount)
		if step.SessionID != sessionID || err != nil || digest != step.PrefixSHA256 {
			// Compaction can replace history. Re-authorize the new exact prefix
			// from actual selections and fresh local receipt verification below.
			working, steps = original, nil
			break
		}
		working, _, err = agent.ProjectNativeHistoryPrefix(working, sessionID, step.Source, step.PrefixCount)
		if err != nil {
			return ctx, original, err
		}
	}
	changed := false
	for {
		identity, count, foreign, err := agent.NativeHistoryBoundary(working, sessionID, p.identity)
		if err != nil {
			return ctx, original, err
		}
		if !foreign {
			break
		}
		source := agent.NativeHistorySource{ProfileID: identity.ProfileID, Provider: identity.Provider}
		for _, owner := range owners {
			if owner.Identity.ProfileID == identity.ProfileID && owner.Identity.Provider == identity.Provider {
				choice := sourceChoice(owner.Identity)
				found := false
				for _, existing := range source.Choices {
					if existing == choice {
						found = true
						break
					}
				}
				if !found {
					source.Choices = append(source.Choices, choice)
				}
			}
		}
		if len(source.Choices) == 0 {
			return ctx, original, nativeHistoryError("source was not selected for this session")
		}
		projected, proofs, err := agent.ProjectNativeHistoryPrefix(working, sessionID, source, count)
		if err != nil {
			return ctx, original, err
		}
		if err := p.verifySources(ctx, sessionID, source, owners, proofs); err != nil {
			return ctx, original, err
		}
		digest, err := agent.NativeHistoryPrefixDigest(original, count)
		if err != nil {
			return ctx, original, err
		}
		steps = append(steps, nativeHistoryStep{SessionID: sessionID, Source: source, Target: p.identity, PrefixCount: count, PrefixSHA256: digest})
		working, changed = projected, true
	}
	if len(steps) == 0 {
		return ctx, original, nativeHistoryError("missing historical authorization")
	}
	last := steps[len(steps)-1]
	if !sameNativeDestination(last.Target, p.identity) {
		// An earlier grant only authorized its own destination. A new actual
		// selection needs its own checked grant, even if the prefix is readable.
		source := agent.NativeHistorySource{ProfileID: last.Target.ProfileID, Provider: last.Target.Provider, Choices: []agent.NativeModelChoice{sourceChoice(last.Target)}}
		projected, proofs, err := agent.ProjectNativeHistoryPrefix(working, sessionID, source, last.PrefixCount)
		if err != nil {
			return ctx, original, err
		}
		if len(proofs) != 0 {
			return ctx, original, nativeHistoryError("unexpected state in readable handoff bridge")
		}
		steps = append(steps, nativeHistoryStep{SessionID: sessionID, Source: source, Target: p.identity, PrefixCount: last.PrefixCount, PrefixSHA256: last.PrefixSHA256})
		working, changed = projected, true
	}
	if changed {
		record := selection
		record.Record, record.Steps = "handoff", steps
		if err := p.s.appendNativeHistory(ctx, scope, record); err != nil {
			return ctx, original, nativeHistoryError("cannot persist historical authorization")
		}
	}
	meta, _ := llmrec.HandoffMetadataFrom(ctx)
	meta.ToModel, meta.PrefixCount = p.identity.Model, steps[len(steps)-1].PrefixCount
	if meta.Kind == "" {
		meta.Kind = "provider_rotation"
	}
	for _, step := range steps {
		for _, choice := range step.Source.Choices {
			meta.FromModels = append(meta.FromModels, choice.Model)
		}
	}
	return llmrec.WithHandoffMetadata(ctx, meta), working, nil
}

func (p *nativeHistoryProvider) verifySources(ctx context.Context, sessionID string, source agent.NativeHistorySource, owners []nativeHistoryRecord, proofs []agent.NativeHistoryProof) error {
	if len(proofs) == 0 || p.s.nativeProxy == nil {
		return nativeHistoryError("source receipts cannot be verified")
	}
	groups := make(map[agent.NativeModelChoice][]agent.NativeHistoryProof)
	for _, proof := range proofs {
		groups[proof.Choice] = append(groups[proof.Choice], proof)
	}
	for choice, group := range groups {
		verified := false
		seen := make(map[string]bool)
		for _, owner := range owners {
			if owner.Identity.ProfileID != source.ProfileID || owner.Identity.Provider != source.Provider || sourceChoice(owner.Identity) != choice || seen[owner.ThinkingType] {
				continue
			}
			seen[owner.ThinkingType] = true
			candidate := source
			candidate.ThinkingType = owner.ThinkingType
			body, err := agent.NativeHistoryVerifyBody(sessionID, candidate, group)
			if err == nil {
				err = p.s.nativeProxy.VerifyReplay(ctx, source.ProfileID, body)
			}
			if err == nil {
				verified = true
				break
			}
		}
		if !verified {
			return nativeHistoryError("source receipt, model or credential binding was rejected")
		}
	}
	return nil
}
