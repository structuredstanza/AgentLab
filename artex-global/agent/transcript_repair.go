package agent

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/structuredstanza/norma/transcript"
)

// repairTranscript drops a partial trailing line from a session transcript.
//
// A crash or a full disk can leave the last JSONL record half-written. Resume
// then rejects the whole file, and because the transcript id is deterministic
// per intent, every retry hits the same bytes — so the intent can never make
// progress again. Cutting the incomplete tail keeps every complete record and
// makes the file readable again.
//
// Only the trailing fragment is removed. A corrupt record in the middle is not
// something this can fix safely, so the caller quarantines the file instead.
func repairTranscript(store *transcript.Store, sessionID string) error {
	if store == nil || sessionID == "" {
		return fmt.Errorf("no transcript store or session id")
	}
	path := store.MainPath(sessionID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// A complete record always ends in '\n', so anything after the last one is
	// the fragment. With no newline at all the file holds no complete record.
	keep := bytes.LastIndexByte(data, '\n') + 1
	if keep == len(data) {
		// The file already ends on a record boundary: the damage is elsewhere.
		return fmt.Errorf("transcript %s has no partial trailing line to drop", path)
	}
	if err := os.WriteFile(path, data[:keep], 0o600); err != nil {
		return err
	}
	return nil
}

// quarantineTranscript moves an unreadable transcript aside so a fresh one can
// be started under the same id.
//
// The file is kept rather than deleted: it is the only record of what the
// intent already did, and an operator may want it for a post-mortem.
func quarantineTranscript(store *transcript.Store, sessionID string) error {
	if store == nil || sessionID == "" {
		return fmt.Errorf("no transcript store or session id")
	}
	path := store.MainPath(sessionID)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	aside := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
	return os.Rename(path, aside)
}
