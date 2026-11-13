package privacy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
)

// Replayed is one previously admitted opaque native state and its receipt.
type Replayed struct {
	State   []byte
	Receipt string
}

// Turn is the admitted identity of a conversation whose opaque state may be replayed.
type Turn struct {
	Binding contract.Binding
	Replay  []Replayed
}

type turnKey struct{}

// WithTurn attaches an admitted turn to the request context used for outbound admission.
func WithTurn(ctx context.Context, t Turn) context.Context {
	return context.WithValue(ctx, turnKey{}, t)
}

func turnFrom(ctx context.Context) (Turn, bool) {
	t, ok := ctx.Value(turnKey{}).(Turn)
	return t, ok
}

// verifyReplay admits complete opaque-bearing native blocks only when their
// source states have valid receipts for this turn and the block order matches.
func verifyReplay(ctx context.Context, rc contract.Receipts, opaque []string) error {
	if len(opaque) == 0 {
		return nil
	}
	t, ok := turnFrom(ctx)
	if !ok || rc == nil || t.Binding.CredentialID == "" {
		return contract.ErrDenied
	}
	var covered []string
	for _, r := range t.Replay {
		if err := rc.Verify(r.Receipt, t.Binding, r.State); err != nil {
			return contract.ErrDenied
		}
		var state any
		dec := json.NewDecoder(bytes.NewReader(r.State))
		dec.UseNumber()
		if dec.Decode(&state) != nil {
			return contract.ErrDenied
		}
		if _, err := dec.Token(); err != io.EOF || collectOpaqueBlocks(state, &covered) != nil {
			return contract.ErrDenied
		}
	}
	if len(covered) != len(opaque) {
		return contract.ErrDenied
	}
	for i := range opaque {
		if opaque[i] != covered[i] {
			return contract.ErrDenied
		}
	}
	return nil
}

func collectOpaqueBlocks(v any, blocks *[]string) error {
	switch x := v.(type) {
	case map[string]any:
		typ, _ := x["type"].(string)
		hasOpaque := false
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := x[key]
			if isOpaque(key, typ) {
				if _, ok := value.(string); !ok {
					return contract.ErrDenied
				}
				hasOpaque = true
				continue
			}
			if err := collectOpaqueBlocks(value, blocks); err != nil {
				return err
			}
		}
		if hasOpaque {
			block, err := json.Marshal(x)
			if err != nil {
				return contract.ErrDenied
			}
			*blocks = append(*blocks, string(block))
		}
	case []any:
		for _, value := range x {
			if err := collectOpaqueBlocks(value, blocks); err != nil {
				return err
			}
		}
	}
	return nil
}
