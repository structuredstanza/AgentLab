package infer

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"

	"github.com/artex/cliproxyhost/internal/contract"
)

const (
	maxInputBytes   = 8 << 20
	maxSessionBytes = 256
)

// opaqueKeys name native fields carrying provider-issued signed or encrypted state.
var opaqueKeys = map[string]bool{
	"signature":         true,
	"thoughtSignature":  true,
	"thought_signature": true,
	"encrypted_content": true,
}

func findModel(models []contract.Model, id string) (contract.Model, bool) {
	for _, m := range models {
		if m.ID == id {
			return m, true
		}
	}
	return contract.Model{}, false
}

// parseInput checks the caller input is a bounded JSON object for the requested model.
func parseInput(raw json.RawMessage, model string) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes {
		return nil, fail(CodeInvalid)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil || doc == nil {
		return nil, fail(CodeInvalid)
	}
	if m, ok := doc["model"]; ok && m != model {
		return nil, fail(CodeInvalid)
	}
	return doc, nil
}

// effortOf reads the reasoning effort from its native location. Antigravity has none.
func effortOf(p contract.Provider, doc map[string]any) string {
	switch p {
	case contract.ProviderClaude:
		return str(obj(doc, "output_config"), "effort")
	case contract.ProviderCodex:
		return str(obj(doc, "reasoning"), "effort")
	}
	return ""
}

// verifyReplay admits every state by receipt and matches opaque fields exactly.
func verifyReplay(r contract.Receipts, b contract.Binding, replay []Replay, doc map[string]any) error {
	var admitted []string
	for _, item := range replay {
		state, err := canonicalJSON(item.State)
		if err != nil {
			return contract.ErrDenied
		}
		if err := r.Verify(item.Receipt, b, state); err != nil {
			return contract.ErrDenied
		}
		var stateDoc map[string]any
		if err := json.Unmarshal(state, &stateDoc); err != nil {
			return contract.ErrDenied
		}
		collectOpaque(stateDoc, &admitted)
	}
	var opaque []string
	collectOpaque(doc, &opaque)
	for _, v := range opaque {
		covered := slices.Contains(admitted, v)
		if !covered {
			return contract.ErrDenied
		}
	}
	return nil
}

func collectOpaque(v any, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		if t["type"] == "redacted_thinking" {
			if s, ok := t["data"].(string); ok && s != "" {
				*out = append(*out, s)
			}
		}
		for k, c := range t {
			if s, ok := c.(string); ok && opaqueKeys[k] {
				if s != "" {
					*out = append(*out, s)
				}
				continue
			}
			collectOpaque(c, out)
		}
	case []any:
		for _, c := range t {
			collectOpaque(c, out)
		}
	}
}

var errNotObject = errors.New("infer: not a JSON object")

// decodeObject parses one JSON object, keeping numbers as literals.
func decodeObject(raw []byte) (map[string]any, error) {
	if !json.Valid(raw) {
		return nil, errNotObject
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errNotObject
	}
	return doc, nil
}

// canonicalJSON is the byte form receipts sign and verify over.
func canonicalJSON(raw []byte) ([]byte, error) {
	doc, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}
