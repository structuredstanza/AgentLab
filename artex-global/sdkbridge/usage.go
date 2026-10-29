package sdkbridge

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// UsageWindow is one normalized quota window reported by the bridge (Contract 2).
type UsageWindow struct {
	ID                string     `json:"id"`
	Label             string     `json:"label"`
	UsedFraction      float64    `json:"used_fraction"`
	RemainingFraction float64    `json:"remaining_fraction"`
	ResetsAt          *time.Time `json:"resets_at"`
}

// BridgeUsage is the normalized payload returned by GET /v1/profiles/:id/usage.
type BridgeUsage struct {
	Provider  string        `json:"provider"`
	Plan      *string       `json:"plan"`
	FetchedAt *time.Time    `json:"fetched_at"`
	Windows   []UsageWindow `json:"windows"`
	Error     string        `json:"error,omitempty"`
}

// Usage fetches the subscription quota windows for a profile and provider.
func (c *Client) Usage(ctx context.Context, profileID, provider string) (BridgeUsage, error) {
	var out BridgeUsage
	err := c.doJSON(ctx, "usage", http.MethodGet, profilePath(profileID)+"/usage?provider="+url.QueryEscape(provider), nil, &out)
	return out, err
}

// GetProfileUsage is an alias for Usage.
func (c *Client) GetProfileUsage(ctx context.Context, profileID, provider string) (BridgeUsage, error) {
	return c.Usage(ctx, profileID, provider)
}
