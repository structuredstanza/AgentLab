package server

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/structuredstanza/AgentLab/artex-global/agent"
	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/llmrec"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/transcript"
)

var errLLMProfileUnavailable = errors.New("selected LLM profile is unavailable")

type preparedLLM struct {
	provider, direct llm.Provider
	chat             *agent.ChatAgent
	cfg              agent.Config
	profileID        int64
	profileName      string
	generation       uint64
}

// prepareLLM leaves the selected identity and live runtime untouched.
func (s *Server) prepareLLM(cfg agent.Config, p *db.LLMProfile) (*preparedLLM, error) {
	s.provCacheMu.Lock()
	generation := s.provCacheGen
	s.provCacheMu.Unlock()
	r := &preparedLLM{cfg: cfg, generation: generation}
	if p != nil {
		r.profileID, r.profileName = p.ID, p.Name
		var resolved agent.Config
		var ok bool
		r.direct, resolved, ok = s.providerForProfile(p.ID)
		if !ok {
			return nil, errLLMProfileUnavailable
		}
		if resolved != cfg {
			return nil, errors.New("LLM profile changed while preparing its runtime")
		}
	} else {
		var err error
		r.direct, err = cfg.NewProvider()
		if err != nil {
			return nil, err
		}
		r.direct = llmrec.Wrap(r.direct, s.m.PG(), cfg.Model, "", cfg.ThinkingType, cfg.ReasoningEffort, s.m.LLMRecordEnabled)
		r.direct = bindSideProvider(r.direct, cfg, 0, "")
	}
	r.provider = r.direct
	if p != nil {
		r.provider = s.poolForActive(p.ID, r.direct, cfg)
	}
	tx := transcript.NewStore(filepath.Join(s.m.dir, "transcripts"))
	r.chat = agent.NewChatAgent(r.provider, cfg.Model, s.m.dir, tx, cfg.CompactionWindow())
	r.chat.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	r.chat.SetWebSearch(s.m.WebSearchOpts())
	r.chat.SetGuard(s.chatGuard())
	r.chat.SetNonStreaming(nonStreamingResolver(cfg))
	r.chat.SetMaxTokens(maxTokensResolver(cfg))
	r.chat.SetNoaEnabled(s.m.NoaCompactionEnabled)
	return r, nil
}

// publishLLM requires provCacheMu: invalidation cannot publish a stale build.
func (s *Server) publishLLM(r *preparedLLM) {
	s.cfgMu.Lock()
	s.llmProv, s.llmDirect, s.chatAgent = r.provider, r.direct, r.chat
	s.llmCfg, s.llmProf, s.llmProfileID, s.llmOn = r.cfg, r.profileName, r.profileID, true
	s.cfgMu.Unlock()
}

func (s *Server) wakeLLM() {
	s.invalidateTaskAgents()
	if t := s.m.ActiveTask(); t != nil {
		t.Notify()
	}
}

func (s *Server) disableLLM(p *db.LLMProfile) {
	var cfg agent.Config
	if p != nil {
		cfg = s.configForProfile(p)
	}
	s.cfgMu.Lock()
	s.llmOn, s.llmProv, s.llmDirect, s.chatAgent = false, nil, nil, nil
	if p != nil {
		s.llmCfg, s.llmProf, s.llmProfileID = cfg, p.Name, p.ID
	}
	s.cfgMu.Unlock()
	s.invalidateTaskAgents()
}

func (s *Server) clearLLMForProfile(id int64, generation uint64) {
	s.provCacheMu.Lock()
	if generation != s.provCacheGen {
		s.provCacheMu.Unlock()
		return
	}
	s.cfgMu.Lock()
	changed := s.llmProfileID == id && s.llmOn
	if changed {
		s.llmOn, s.llmProv, s.llmDirect, s.chatAgent = false, nil, nil, nil
	}
	s.cfgMu.Unlock()
	s.provCacheMu.Unlock()
}

func (s *Server) reapplyActiveProfile() error {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	return s.reapplyActiveProfileLocked()
}

func (s *Server) reapplyActiveProfileLocked() error {
	p, err := s.m.pg.ActiveProfile()
	if err != nil {
		s.disableLLM(nil)
		return err
	}
	var cfg agent.Config
	if p != nil {
		cfg = s.configForProfile(p)
	} else {
		var ok bool
		cfg, ok = agent.FromEnv()
		if !ok {
			s.disableLLM(nil)
			return nil
		}
	}
	for {
		r, err := s.prepareLLM(cfg, p)
		if err != nil {
			s.disableLLM(p)
			return err
		}
		s.provCacheMu.Lock()
		if r.generation != s.provCacheGen {
			s.provCacheMu.Unlock()
			continue
		}
		s.publishLLM(r)
		s.provCacheMu.Unlock()
		s.wakeLLM()
		return nil
	}
}

// activateProfile prepares before committing selection, then publishes one runtime.
func (s *Server) activateProfile(id int64) error {
	p, err := s.m.pg.ProfileByID(id)
	if err != nil {
		return err
	}
	if p == nil {
		return db.ErrLLMProfileNotFound
	}
	cfg := s.configForProfile(p)
	for {
		r, err := s.prepareLLM(cfg, p)
		if err != nil {
			return fmt.Errorf("cannot activate LLM profile: %w", err)
		}
		s.provCacheMu.Lock()
		if r.generation != s.provCacheGen {
			s.provCacheMu.Unlock()
			continue
		}
		if err := s.m.pg.SetActiveProfile(id); err != nil {
			s.provCacheMu.Unlock()
			return err
		}
		s.profChatAgents = map[int64]*agent.ChatAgent{}
		s.provCacheGen++
		s.publishLLM(r)
		s.provCacheMu.Unlock()
		s.wakeLLM()
		return nil
	}
}

func (s *Server) globalLLMReady() bool {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	s.cfgMu.Lock()
	id, on, auth := s.llmProfileID, s.llmOn, s.llmCfg.AuthMethod
	s.cfgMu.Unlock()
	if !on || id == 0 || auth == "" || auth == "api_key" {
		return on
	}
	p, err := s.m.pg.ProfileByID(id)
	if err != nil || !s.profileUsable(p) {
		s.disableLLM(p)
		return false
	}
	return true
}
