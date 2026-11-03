package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/sidequestion"
	"github.com/Autumn-27/norma/llm"
)

type NativeModelChoice struct {
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
}

type NativeHistoryIdentity struct {
	ProfileID       string `json:"profile_id"`
	Provider        string `json:"provider"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
}

type NativeHistorySource struct {
	ProfileID    string              `json:"profile_id"`
	Provider     string              `json:"provider"`
	ThinkingType string              `json:"thinking_type,omitempty"`
	Choices      []NativeModelChoice `json:"choices"`
}

// NativeHistoryProof stays local: the router verifies it with the native host
// before persisting authorization to disclose a readable historical prefix.
type NativeHistoryProof struct {
	Choice  NativeModelChoice
	State   json.RawMessage
	Receipt string
}

// NativeHistoryTail is an untrusted routing hint, never handoff authorization.
func NativeHistoryTail(req llm.CompletionRequest, sessionID string) (NativeHistoryIdentity, bool, error) {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		message := req.Messages[i]
		env, found, err := nativeEnvelope(message)
		if err != nil {
			return NativeHistoryIdentity{}, false, fmt.Errorf("%w: %v", llm.ErrHistoryRejected, err)
		}
		if !found {
			continue
		}
		if message.Role != llm.RoleAssistant || env.Version != 2 || env.SessionID != sessionID || sessionID == "" || env.ProfileID == "" || env.Provider == "" || env.Model == "" || env.ResponseID == "" || env.Receipt == "" || len(env.State) == 0 {
			return NativeHistoryIdentity{}, false, fmt.Errorf("%w: invalid source envelope", llm.ErrHistoryRejected)
		}
		return NativeHistoryIdentity{ProfileID: env.ProfileID, Provider: env.Provider, Model: env.Model, ReasoningEffort: env.ReasoningEffort}, true, nil
	}
	return NativeHistoryIdentity{}, false, nil
}

func nativeHistoryRange(req llm.CompletionRequest, count int) (int, int, error) {
	start := req.EphemeralPrefix
	if start < 0 || start > len(req.Messages) || count <= 0 || count > len(req.Messages)-start {
		return 0, 0, fmt.Errorf("%w: invalid historical prefix bounds", llm.ErrHistoryRejected)
	}
	return start, start + count, nil
}

// NativeHistoryPrefixDigest excludes only SDK-declared ephemeral host reminders,
// so a new date/reminder after transcript resume cannot invalidate the history.
func NativeHistoryPrefixDigest(req llm.CompletionRequest, count int) (string, error) {
	start, end, err := nativeHistoryRange(req, count)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(req.Messages[start:end])
	if err != nil {
		return "", fmt.Errorf("%w: malformed historical prefix", llm.ErrHistoryRejected)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// ProjectNativeHistoryPrefix validates source identity, configured choices and
// every neutral projection. The caller must authorize the transition and verify
// the returned receipts; this pure operation never grants replay authority.
func ProjectNativeHistoryPrefix(req llm.CompletionRequest, sessionID string, source NativeHistorySource, count int) (llm.CompletionRequest, []NativeHistoryProof, error) {
	start, end, err := nativeHistoryRange(req, count)
	if err != nil {
		return req, nil, err
	}
	if sessionID == "" || source.ProfileID == "" || source.Provider == "" || len(source.Choices) == 0 {
		return req, nil, fmt.Errorf("%w: incomplete source binding", llm.ErrHistoryRejected)
	}
	messages := append([]llm.Message(nil), req.Messages...)
	var proofs []NativeHistoryProof
	for i := start; i < end; i++ {
		message := req.Messages[i]
		env, found, err := nativeEnvelope(message)
		if err != nil {
			return req, nil, fmt.Errorf("%w: %v", llm.ErrHistoryRejected, err)
		}
		if found {
			choice := NativeModelChoice{Model: env.Model, ReasoningEffort: env.ReasoningEffort}
			if message.Role != llm.RoleAssistant || env.Version != 2 || env.ProfileID != source.ProfileID || env.Provider != source.Provider || env.SessionID != sessionID || env.ResponseID == "" || env.Receipt == "" || len(env.State) == 0 || !isAllowedFallbackChoice(source.Choices, choice) {
				return req, nil, fmt.Errorf("%w: foreign, legacy or unapproved source state", llm.ErrHistoryRejected)
			}
			projected, responseID, err := projectNative(env.Provider, env.State)
			if err != nil || (responseID != "" && responseID != env.ResponseID) || !sameNativeProjection(stripNativeState(message.Content), projected) {
				return req, nil, fmt.Errorf("%w: source state conflicts with its neutral projection", llm.ErrHistoryRejected)
			}
			proofs = append(proofs, NativeHistoryProof{Choice: choice, State: env.State, Receipt: env.Receipt})
		}
		readable, err := sidequestion.ReadableHistoryMessage(message)
		if err != nil {
			return req, nil, fmt.Errorf("%w: %v", llm.ErrHistoryRejected, err)
		}
		messages[i] = readable
	}
	req.Messages = messages
	return req, proofs, nil
}

// NativeHistoryBoundary finds the oldest source run that must become readable.
// It is only a routing hint: source receipts and selection authority are checked
// by the router before any transformed request can be dispatched.
func NativeHistoryBoundary(req llm.CompletionRequest, sessionID string, target NativeHistoryIdentity) (NativeHistoryIdentity, int, bool, error) {
	var first NativeHistoryIdentity
	boundary := len(req.Messages)
	foreign := false
	for i, message := range req.Messages {
		identity, found, err := NativeHistoryTail(llm.CompletionRequest{Messages: []llm.Message{message}}, sessionID)
		if err != nil {
			return first, 0, false, err
		}
		if !found {
			continue
		}
		if i < req.EphemeralPrefix {
			return first, 0, false, fmt.Errorf("%w: native state in ephemeral prefix", llm.ErrHistoryRejected)
		}
		if first.ProfileID == "" {
			first = identity
		}
		if identity.ProfileID != first.ProfileID || identity.Provider != first.Provider {
			if boundary == len(req.Messages) {
				boundary = i
			}
		}
		if identity.ProfileID != target.ProfileID || identity.Provider != target.Provider {
			foreign = true
		}
	}
	return first, boundary - req.EphemeralPrefix, foreign, nil
}

// NativeHistoryVerifyBody reconstructs only the source's local catalog inputs;
// it never sends old thinking or signatures to a different provider.
func NativeHistoryVerifyBody(sessionID string, source NativeHistorySource, proofs []NativeHistoryProof) (json.RawMessage, error) {
	if len(proofs) == 0 {
		return nil, fmt.Errorf("%w: missing source receipts", llm.ErrHistoryRejected)
	}
	choice := proofs[0].Choice
	replay := make([]nativeReplay, len(proofs))
	for i, proof := range proofs {
		if proof.Choice != choice {
			return nil, fmt.Errorf("%w: mixed receipt model choices", llm.ErrHistoryRejected)
		}
		replay[i] = nativeReplay{State: proof.State, Receipt: proof.Receipt}
	}
	p := nativeProvider{provider: source.Provider, model: choice.Model, effort: choice.ReasoningEffort, thinking: source.ThinkingType}
	input, err := p.encodeInput(llm.CompletionRequest{})
	if err != nil {
		return nil, err
	}
	return json.Marshal(nativeInferBody{Provider: source.Provider, Model: choice.Model, SessionID: sessionID, Input: input, Replay: replay})
}
