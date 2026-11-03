package infer

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/artex/cliproxyhost/internal/contract"
	"github.com/artex/cliproxyhost/internal/privacy"
)

func TestVerifyReplayOfflineRealReceiptBindings(t *testing.T) {
	receipts, err := privacy.NewReceipts(filepath.Join(t.TempDir(), "receipt.key"))
	if err != nil {
		t.Fatal(err)
	}
	state := json.RawMessage(`{"id":"turn","content":[{"type":"tool_use","id":"tool","name":"inspect","input":{"n":9007199254740993}}]}`)
	canonical, err := canonicalJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	binding := contract.Binding{Provider: contract.ProviderClaude, Model: "model", Profile: "1", SessionID: "session", CredentialID: "current-credential"}
	receipt, err := receipts.Sign(binding, canonical)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"valid", "profile", "provider", "session", "model", "epoch", "state", "receipt", "empty"} {
		t.Run(change, func(t *testing.T) {
			req := InferRequest{Profile: "1", Provider: contract.ProviderClaude, Model: "model", SessionID: "session", Replay: []Replay{{State: state, Receipt: receipt}}}
			switch change {
			case "profile":
				req.Profile = "2"
			case "provider":
				req.Provider = contract.ProviderCodex
			case "session":
				req.SessionID = "other"
			case "model":
				req.Model = "other-model"
			case "epoch":
				altered := binding
				altered.CredentialID = "old-credential"
				req.Replay[0].Receipt, _ = receipts.Sign(altered, canonical)
			case "state":
				req.Replay[0].State = json.RawMessage(`{"content":[{"input":{"n":9007199254740994}}]}`)
			case "receipt":
				req.Replay[0].Receipt = "invalid"
			case "empty":
				req.Replay = nil
			}
			releases := 0
			service := &Service{d: Deps{Store: &loadedStoreFixture{}, Catalog: catalogFixture{}, Receipts: receipts, Streamer: forbiddenStreamerFixture{t}, Acquire: func(ctx context.Context, _ contract.ProfileID) (context.Context, func(), error) {
				return ctx, func() { releases++ }, nil
			}, Turn: func(context.Context, contract.Binding, []Replay) context.Context {
				t.Fatal("offline verification entered provider execution context")
				return nil
			}}}
			err := service.VerifyReplay(context.Background(), req)
			if (err == nil) != (change == "valid") {
				t.Fatalf("receipt binding %s: %v", change, err)
			}
			if change != "empty" && change != "model" && releases != 1 {
				t.Fatalf("profile lease released %d times", releases)
			}
		})
	}
}
