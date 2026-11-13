package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/nativeproxy"
)

var (
	usageCacheInst *usageCache
	usageCacheOnce sync.Once
)

func (s *Server) getUsageCache() *usageCache {
	usageCacheOnce.Do(func() {
		usageCacheInst = newUsageCache()
	})
	return usageCacheInst
}

// ProfileUsageEntry matches Contract 3 for a single profile quota status.
type ProfileUsageEntry struct {
	ProfileID  string                    `json:"profile_id"`
	Name       string                    `json:"name"`
	AuthMethod string                    `json:"auth_method"`
	Connected  bool                      `json:"connected"`
	Plan       *string                   `json:"plan"`
	FetchedAt  *time.Time                `json:"fetched_at"`
	Stale      bool                      `json:"stale"`
	Windows    []nativeproxy.UsageWindow `json:"windows"`
	Error      string                    `json:"error,omitempty"`
}

// UsageListResponse is returned by GET /api/llm/usage.
type UsageListResponse struct {
	Profiles []ProfileUsageEntry `json:"profiles"`
}

func (s *Server) getOrFetchUsage(ctx context.Context, p *db.LLMProfile) ProfileUsageEntry {
	pidStr := strconv.FormatInt(p.ID, 10)
	provider := nativeProxyProvider(p.AuthMethod)
	emptyWindows := []nativeproxy.UsageWindow{}

	// API-key or non-subscription profiles should never call upstream
	if provider == "" {
		return ProfileUsageEntry{
			ProfileID:  pidStr,
			Name:       p.Name,
			AuthMethod: p.AuthMethod,
			Connected:  false,
			Plan:       nil,
			FetchedAt:  nil,
			Stale:      false,
			Windows:    emptyWindows,
		}
	}

	if s.nativeProxy == nil {
		return ProfileUsageEntry{
			ProfileID:  pidStr,
			Name:       p.Name,
			AuthMethod: p.AuthMethod,
			Connected:  false,
			Plan:       nil,
			FetchedAt:  nil,
			Stale:      false,
			Windows:    emptyWindows,
			Error:      errNativeProxyUnavailable.Error(),
		}
	}

	cache := s.getUsageCache()
	st, err := s.nativeProxyProfileStatus(ctx, p)
	if err != nil {
		cached, _, _, hasLastGood := cache.get(p.ID, time.Now())
		if hasLastGood {
			wins := cached.windows
			if wins == nil {
				wins = emptyWindows
			}
			return ProfileUsageEntry{
				ProfileID:  pidStr,
				Name:       p.Name,
				AuthMethod: p.AuthMethod,
				Connected:  true,
				Plan:       cached.plan,
				FetchedAt:  cached.fetchedAt,
				Stale:      true,
				Windows:    wins,
				Error:      "status_unavailable",
			}
		}
		return ProfileUsageEntry{
			ProfileID:  pidStr,
			Name:       p.Name,
			AuthMethod: p.AuthMethod,
			Connected:  false,
			Plan:       nil,
			FetchedAt:  nil,
			Stale:      false,
			Windows:    emptyWindows,
			Error:      "status_unavailable",
		}
	}
	if !st.Connected {
		return ProfileUsageEntry{
			ProfileID:  pidStr,
			Name:       p.Name,
			AuthMethod: p.AuthMethod,
			Connected:  false,
			Plan:       nil,
			FetchedAt:  nil,
			Stale:      false,
			Windows:    emptyWindows,
		}
	}

	now := time.Now()
	cached, hitFresh, inBackoff, hasLastGood := cache.get(p.ID, now)

	if hitFresh {
		wins := cached.windows
		if wins == nil {
			wins = emptyWindows
		}
		return ProfileUsageEntry{
			ProfileID:  pidStr,
			Name:       p.Name,
			AuthMethod: p.AuthMethod,
			Connected:  true,
			Plan:       cached.plan,
			FetchedAt:  cached.fetchedAt,
			Stale:      false,
			Windows:    wins,
		}
	}

	if inBackoff {
		wins := cached.windows
		if wins == nil {
			wins = emptyWindows
		}
		if hasLastGood {
			return ProfileUsageEntry{
				ProfileID:  pidStr,
				Name:       p.Name,
				AuthMethod: p.AuthMethod,
				Connected:  true,
				Plan:       cached.plan,
				FetchedAt:  cached.fetchedAt,
				Stale:      true,
				Windows:    wins,
				Error:      "rate_limited",
			}
		}
		return ProfileUsageEntry{
			ProfileID:  pidStr,
			Name:       p.Name,
			AuthMethod: p.AuthMethod,
			Connected:  true,
			Plan:       nil,
			FetchedAt:  nil,
			Stale:      false,
			Windows:    emptyWindows,
			Error:      "rate_limited",
		}
	}

	// Fetch upstream via native proxy
	proxyUsage, err := s.nativeProxy.Usage(ctx, pidStr, provider)
	if err != nil {
		var be *nativeproxy.Error
		errCode := "upstream_error"
		if errors.As(err, &be) {
			if be.Status == http.StatusTooManyRequests || be.Code == "rate_limited" {
				cache.setRateLimited(p.ID, now)
				errCode = "rate_limited"
			} else if be.Status == http.StatusConflict && be.Code == "not_connected" {
				return ProfileUsageEntry{
					ProfileID:  pidStr,
					Name:       p.Name,
					AuthMethod: p.AuthMethod,
					Connected:  false,
					Plan:       nil,
					FetchedAt:  nil,
					Stale:      false,
					Windows:    emptyWindows,
				}
			} else if be.Code != "" {
				errCode = be.Code
			}
		}

		if hasLastGood {
			wins := cached.windows
			if wins == nil {
				wins = emptyWindows
			}
			return ProfileUsageEntry{
				ProfileID:  pidStr,
				Name:       p.Name,
				AuthMethod: p.AuthMethod,
				Connected:  true,
				Plan:       cached.plan,
				FetchedAt:  cached.fetchedAt,
				Stale:      true,
				Windows:    wins,
				Error:      errCode,
			}
		}

		return ProfileUsageEntry{
			ProfileID:  pidStr,
			Name:       p.Name,
			AuthMethod: p.AuthMethod,
			Connected:  true,
			Plan:       nil,
			FetchedAt:  nil,
			Stale:      false,
			Windows:    emptyWindows,
			Error:      errCode,
		}
	}

	fetchedAt := proxyUsage.FetchedAt
	if fetchedAt == nil {
		t := time.Now()
		fetchedAt = &t
	}
	cache.set(p.ID, proxyUsage.Plan, fetchedAt, proxyUsage.Windows, now)

	wins := proxyUsage.Windows
	if wins == nil {
		wins = emptyWindows
	}

	return ProfileUsageEntry{
		ProfileID:  pidStr,
		Name:       p.Name,
		AuthMethod: p.AuthMethod,
		Connected:  true,
		Plan:       proxyUsage.Plan,
		FetchedAt:  fetchedAt,
		Stale:      false,
		Windows:    wins,
	}
}

func (s *Server) getProfileUsage(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid LLM profile id")
		return
	}
	p, err := pg.ProfileByID(id)
	if err != nil {
		writeErr(w, 500, "could not load LLM profile")
		return
	}
	if p == nil {
		writeErr(w, 404, "LLM profile not found")
		return
	}
	if nativeProxyProvider(p.AuthMethod) == "" {
		writeErr(w, 400, "subscription usage is only available for OAuth profiles")
		return
	}

	entry := s.getOrFetchUsage(r.Context(), p)
	writeJSON(w, 200, entry)
}

func (s *Server) getUsage(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	profiles, err := pg.ListProfiles()
	if err != nil {
		writeErr(w, 500, "could not load LLM profiles")
		return
	}

	var results []ProfileUsageEntry
	for _, p := range profiles {
		if nativeProxyProvider(p.AuthMethod) == "" {
			continue // api-key profiles omitted
		}
		entry := s.getOrFetchUsage(r.Context(), p)
		results = append(results, entry)
	}

	if results == nil {
		results = []ProfileUsageEntry{}
	}
	writeJSON(w, 200, UsageListResponse{Profiles: results})
}
