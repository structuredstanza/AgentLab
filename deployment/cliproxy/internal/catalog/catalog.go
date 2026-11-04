// Package catalog serves the pinned core's local model metadata without network probes.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/artex/cliproxyhost/internal/contract"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy"
)

// ErrUnknownProvider is returned for a provider with no catalog section.
var ErrUnknownProvider = errors.New("unknown provider")

// Catalog is the embedded model catalog. It is read-only after New.
type Catalog struct {
	models map[contract.Provider][]contract.Model
}

var _ contract.Catalog = (*Catalog)(nil)

// New projects the same embedded metadata used by the native executor registry.
func New() (*Catalog, error) {
	c := &Catalog{models: make(map[contract.Provider][]contract.Model, 3)}
	for _, p := range []contract.Provider{contract.ProviderClaude, contract.ProviderCodex, contract.ProviderAntigravity} {
		models, err := core.NativeModels(string(p))
		if err != nil {
			return nil, fmt.Errorf("load native catalog: %w", err)
		}
		for _, m := range models {
			c.models[p] = append(c.models[p], contract.Model{
				ID: m.ID, Name: m.Name, ContextWindow: m.ContextWindow,
				SupportedEfforts: m.SupportedEfforts,
			})
			if p == contract.ProviderAntigravity && m.ID == "gemini-4-argon-high" {
				c.models[p] = append(c.models[p], contract.Model{
					ID: "gemini-4-argon", Name: m.Name, ContextWindow: m.ContextWindow,
					SupportedEfforts: []string{"low", "medium", "high"},
				})
			}
		}
	}
	return c, nil
}

// Models returns a deep copy of the catalog entries for provider, so callers
// cannot mutate the embedded data.
// AddCustom registers the operator-hosted models. They cannot come from the embedded
// native registry because nothing is known about them statically, so the host supplies
// them from its own configuration.
func (c *Catalog) AddCustom(models []contract.Model) {
	c.models[contract.ProviderCustom] = models
}

func (c *Catalog) Models(provider contract.Provider) ([]contract.Model, error) {
	src, ok := c.models[provider]
	if !ok {
		return nil, ErrUnknownProvider
	}
	out := make([]contract.Model, len(src))
	for i, m := range src {
		efforts := make([]string, len(m.SupportedEfforts))
		copy(efforts, m.SupportedEfforts)
		m.SupportedEfforts = efforts
		out[i] = m
	}
	return out, nil
}

// Resolve retains the configured logical Argon model and selects its native thinking SKU.
func Resolve(provider contract.Provider, model string, input json.RawMessage) (string, json.RawMessage, error) {
	if provider != contract.ProviderAntigravity || model != "gemini-4-argon" {
		return model, input, nil
	}
	var body struct {
		GenerationConfig struct {
			ThinkingConfig struct {
				ThinkingLevel string `json:"thinkingLevel"`
			} `json:"thinkingConfig"`
		} `json:"generationConfig"`
	}
	if err := json.Unmarshal(input, &body); err != nil {
		return "", nil, errors.New("invalid native thinking configuration")
	}
	level := body.GenerationConfig.ThinkingConfig.ThinkingLevel
	if level == "" {
		level = "low"
	}
	switch level {
	case "low", "medium", "high":
		// The native executor sets its envelope model from Request.Model, not the payload.
		return model + "-" + level, input, nil
	default:
		return "", nil, errors.New("unsupported native thinking level")
	}
}
