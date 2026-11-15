// Package manifest turns a tool's invocation and output into data.
//
// A manifest is a TOML file declaring one external tool: what parameters an
// operator may set, how those become an argv, how the tool's output is split
// into records, and which fields of each record become an asset or a fact. It
// exists so that adding a tool is a data change rather than a Go change, and so
// that every tool's parsing is pinned by a captured-output fixture instead of
// by someone's memory of the output format.
//
// The design is deliberately narrow. A manifest cannot run arbitrary code, and
// a rule that fails to resolve is skipped rather than fatal: tools emit partial
// rows constantly, and one missing field in one record must not discard a whole
// scan.
package manifest

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Category groups manifests for display and for ranking a plan.
type Category string

const (
	CategoryRecon   Category = "recon"
	CategoryWeb     Category = "web"
	CategoryScan    Category = "scan"
	CategoryNetwork Category = "network"
	CategoryCreds   Category = "creds"
	CategoryIntel   Category = "intel"
)

// Kind is the shape of an asset a tool accepts or emits.
type Kind string

const (
	KindDomain    Kind = "domain"
	KindSubdomain Kind = "subdomain"
	KindIP        Kind = "ip"
	KindCIDR      Kind = "cidr"
	KindURL       Kind = "url"
)

// ParamType is the control a UI renders for a parameter.
type ParamType string

const (
	ParamString ParamType = "string"
	ParamBool   ParamType = "bool"
	ParamNumber ParamType = "number"
	ParamEnum   ParamType = "enum"
)

// Param declares one operator-settable argument.
type Param struct {
	Type        ParamType `toml:"type"`
	Label       string    `toml:"label"`
	Description string    `toml:"description"`
	Placeholder string    `toml:"placeholder"`
	// Default is rendered into the argv when the operator sets nothing. It is a
	// string in the file and converted per Type, so a manifest stays readable.
	Default string `toml:"default"`
	// Options lists the accepted values for an enum parameter.
	Options []string `toml:"options"`
	// Required rejects a run that leaves it empty, rather than silently running
	// the tool with a missing argument and producing misleading output.
	Required bool `toml:"required"`
}

// Command is the argv template.
type Command struct {
	Program string   `toml:"program"`
	Args    []string `toml:"args"`
	// TimeoutSeconds bounds one run. A tool that hangs must not hold a worker.
	TimeoutSeconds int `toml:"timeout_seconds"`
}

// EmitTarget is a rule that turns a record into an asset.
type EmitTarget struct {
	Kind   Kind   `toml:"kind"`
	Value  string `toml:"value"`
	Parent string `toml:"parent"`
}

// EmitFact is a rule that turns a record into a fact on the input asset.
type EmitFact struct {
	Kind KindOrFact `toml:"kind"`
	Data map[string]string
}

// KindOrFact is a free-form fact label; the vocabulary is the manifest's, not
// the schema's, so a new tool can introduce a new fact kind without a migration.
type KindOrFact string

// Emit declares how records become assets and facts.
type Emit struct {
	// Parser is json, jsonl, lines, or regex.
	Parser string `toml:"parser"`
	// Source is stdout or stderr. stdout is the default.
	Source string `toml:"source"`
	// Records is a JSON path selecting the array to iterate, for parser=json.
	Records string `toml:"records"`
	// Pattern is the regex applied per line, for parser=regex. Named capture
	// groups become record fields.
	Pattern string `toml:"pattern"`
	// Fields selects which record fields to keep, for parser=json/jsonl. Empty
	// keeps everything, which is usually too much; a manifest should narrow.
	Fields []string `toml:"fields"`

	Targets []EmitTarget `toml:"targets"`
	Facts   []EmitFact   `toml:"facts"`
}

// Manifest is one tool.
type Manifest struct {
	ID          string   `toml:"id"`
	Name        string   `toml:"name"`
	Description string   `toml:"description"`
	Category    Category `toml:"category"`
	Accepts     []Kind   `toml:"accepts"`
	// Requires lists binaries that must be on PATH. A manifest whose tool is
	// absent is reported, not silently offered.
	Requires []string `toml:"requires"`

	Params  map[string]Param `toml:"params"`
	Command Command          `toml:"command"`
	Emit    Emit             `toml:"emit"`
	// Limits declares which parameter carries this tool's throughput, so the
	// engagement policy can cap it. A tool that declares nothing is treated as
	// an unbounded requester and is refused under a closed-world policy.
	Limits Limits `toml:"limits"`
	// Install is an optional bash recipe that puts the tool's binary on the
	// box, so an operator can add a tool from the Toolbox without a rebuild.
	Install Install `toml:"install"`
}

// RateUnit is what a tool's throughput parameter counts.
type RateUnit string

const (
	// RateRPS counts HTTP requests per second.
	RateRPS RateUnit = "rps"
	// RatePPS counts packets per second, for raw scanners.
	RatePPS RateUnit = "pps"
	// RateThreads counts parallel workers, for credential tools.
	RateThreads RateUnit = "threads"
	// RateNone means the tool takes no throughput parameter at all.
	RateNone RateUnit = ""
)

// Limits names the parameter that controls throughput.
type Limits struct {
	// Param is the parameter name holding the rate. Empty with Unit set means
	// the tool has a rate but no flag to set it, which the policy refuses.
	Param string   `toml:"param"`
	Unit  RateUnit `toml:"unit"`
}

// defaultInstallTimeoutSeconds bounds an install script that names no timeout:
// package and git installs routinely outlast a scan's default.
const defaultInstallTimeoutSeconds = 600

// Install is how to obtain the tool on this machine.
type Install struct {
	// Script runs under `bash -c`. Empty means the manifest is not installable.
	Script         string `toml:"script"`
	TimeoutSeconds int    `toml:"timeout_seconds"`
}

// Set is a loaded collection of manifests, indexed by id.
type Set struct {
	byID map[string]*Manifest
	ids  []string
}

// Len reports how many manifests loaded.
func (s *Set) Len() int { return len(s.byID) }

// IDs returns the manifest ids in sorted order.
func (s *Set) IDs() []string { return append([]string(nil), s.ids...) }

// Get returns the manifest with this id, or nil.
func (s *Set) Get(id string) *Manifest { return s.byID[id] }

// All returns every manifest in id order.
func (s *Set) All() []*Manifest {
	out := make([]*Manifest, 0, len(s.ids))
	for _, id := range s.ids {
		out = append(out, s.byID[id])
	}
	return out
}

// Overlay returns a new set holding this set plus extra, where an extra
// manifest replaces the member with the same id. The receiver is not modified,
// so a live set can be swapped atomically while readers still hold the old one.
func (s *Set) Overlay(extra []*Manifest) *Set {
	out := &Set{byID: make(map[string]*Manifest, len(s.byID)+len(extra))}
	for id, m := range s.byID {
		out.byID[id] = m
	}
	for _, m := range extra {
		out.byID[m.ID] = m
	}
	for id := range out.byID {
		out.ids = append(out.ids, id)
	}
	sort.Strings(out.ids)
	return out
}

// Parse decodes and validates one manifest.
func Parse(text string) (*Manifest, error) {
	var m Manifest
	md, err := toml.Decode(text, &m)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		// A typo in a key would otherwise be silently ignored and the option
		// would appear not to work.
		return nil, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	if m.Install.TimeoutSeconds < 0 {
		return nil, fmt.Errorf("%s: install.timeout_seconds must not be negative", m.ID)
	}
	if m.Install.Script != "" && m.Install.TimeoutSeconds == 0 {
		m.Install.TimeoutSeconds = defaultInstallTimeoutSeconds
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(m.Command.Program) == "" {
		return fmt.Errorf("%s: command.program is required", m.ID)
	}
	switch m.Category {
	case CategoryRecon, CategoryWeb, CategoryScan, CategoryNetwork, CategoryCreds, CategoryIntel:
	case "":
		return fmt.Errorf("%s: category is required", m.ID)
	default:
		return fmt.Errorf("%s: unknown category %q", m.ID, m.Category)
	}
	for _, k := range m.Accepts {
		if !validKind(k) {
			return fmt.Errorf("%s: unknown accepts kind %q", m.ID, k)
		}
	}
	switch m.Emit.Parser {
	case "json", "jsonl", "lines", "regex", "xml":
	case "":
		return fmt.Errorf("%s: emit.parser is required", m.ID)
	default:
		return fmt.Errorf("%s: unknown emit.parser %q", m.ID, m.Emit.Parser)
	}
	if m.Emit.Parser == "regex" && strings.TrimSpace(m.Emit.Pattern) == "" {
		return fmt.Errorf("%s: emit.pattern is required for parser=regex", m.ID)
	}
	for name, p := range m.Params {
		switch p.Type {
		case ParamString, ParamBool, ParamNumber, ParamEnum:
		case "":
			return fmt.Errorf("%s: param %q has no type", m.ID, name)
		default:
			return fmt.Errorf("%s: param %q has unknown type %q", m.ID, name, p.Type)
		}
		if p.Type == ParamEnum && len(p.Options) == 0 {
			return fmt.Errorf("%s: enum param %q has no options", m.ID, name)
		}
	}
	for _, t := range m.Emit.Targets {
		if !validKind(t.Kind) {
			return fmt.Errorf("%s: emit target kind %q is not an asset kind", m.ID, t.Kind)
		}
	}
	return nil
}

func validKind(k Kind) bool {
	switch k {
	case KindDomain, KindSubdomain, KindIP, KindCIDR, KindURL:
		return true
	}
	return false
}
