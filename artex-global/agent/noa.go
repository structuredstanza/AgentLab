package agent

import (
	"log"
	"path/filepath"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/noaadapter"
)

// noaWarn returns a diagnostics sink tagging non-fatal noa messages with the
// session, routed through the package logger (agents have no per-instance one).
func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

// noa is the "model-driven context compression" mechanism introduced in norma v0.4.0; as a platform experimental feature, the user enables it in
// Toggle in the system settings. It is mutually exclusive with the built-in compaction: noaadapter.Enable is the only entry point, attached in one go
// The context takeover component (Compactor), the Compress tool, and the three resident prompts. If Enable is not called, this stays off
// (built-in compaction continues to work as usual). The toggle is resolved by the noaEnabledFn injected into each agent and is read
// Only once, so switching affects only runs started afterward; no need to rebuild the agent.

// enableNoa wires noa into opts when the resolver reports it as enabled. archiveRoot is the base directory for persisting the original compressed content
// (it takes the global workDir, and every agent places its archives uniformly under <workDir>/noa, rather than scattering them across task/intent directories), sessionID
// names the archive subdirectory beneath it (globally unique, so there is no conflict within the same base directory).
//
// noa is an experimental feature: a failure to wire it in must not interrupt the real task. When an error occurs, report it via onWarn and fall back to built-in compression.
// When enabled, clear opts.Compaction to avoid agentcore warning that two context managers are set at the same time.
func enableNoa(opts *agentcore.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	if err := noaadapter.Enable(opts, noaadapter.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}); err != nil {
		if onWarn != nil {
			onWarn("noa compaction failed to enable, falling back to built-in compaction:" + err.Error())
		}
		return
	}
	// Compactor overrides Compaction, but when both coexist agentcore warns on every call; explicitly clear it.
	opts.Compaction = nil
}
