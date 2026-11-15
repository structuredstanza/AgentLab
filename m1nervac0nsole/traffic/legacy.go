package traffic

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type legacySide struct {
	head          string
	body, preview io.Reader
	hash          string
	file, blob    *os.File
}

func (s *legacySide) close() {
	if s.blob != nil {
		_ = s.blob.Close()
	}
	_ = s.file.Close()
}

// Complete literal bodies take precedence over marker syntax. Only incomplete
// captures with an exact historical marker may resolve content-addressed data.
var legacyMarkerRE = regexp.MustCompile(`(?:\A|\n…\[truncated\] )@blob sha256:([0-9a-f]{64}) \(len=([0-9]+)\)\z`)

func legacyBodyMarker(tail []byte, stored, expected int64) (string, int64, error) {
	match := legacyMarkerRE.FindSubmatchIndex(tail)
	if match == nil || (tail[match[0]] == '@' && stored != int64(len(tail))) {
		return "", 0, fmt.Errorf("legacy traffic body incomplete: expected %d bytes, read %d", expected, stored)
	}
	length, err := strconv.ParseInt(string(tail[match[4]:match[5]]), 10, 64)
	if err != nil || length < 0 {
		return "", 0, errors.New("legacy traffic blob length is invalid")
	}
	if length != expected {
		return "", 0, errors.New("legacy traffic blob length disagrees with captured metadata")
	}
	return string(tail[match[2]:match[3]]), stored - int64(len(tail)) + int64(match[0]), nil
}

func (t *Traffic) openLegacySide(relative, name string, expected int64) (_ *legacySide, err error) {
	if !filepath.IsLocal(relative) {
		return nil, errors.New("legacy traffic path is invalid")
	}
	if expected < 0 {
		return nil, errors.New("legacy traffic body length is negative")
	}
	file, err := os.Open(filepath.Join(t.dir, relative, name))
	if err != nil {
		return nil, err
	}
	side := &legacySide{file: file}
	defer func() {
		if err != nil {
			side.close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	head, reader, separated, err := splitLegacyEvidence(file)
	if err != nil {
		return nil, err
	}
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	offset := position - int64(reader.Buffered())
	stored := info.Size() - offset
	if stored < 0 {
		return nil, errors.New("legacy traffic capture changed while reading")
	}
	if !separated && (expected != 0 || !credibleLegacyHeader(head)) {
		return nil, errors.New("legacy traffic capture has no header separator")
	}
	side.head = head
	if stored == expected {
		side.body = io.NewSectionReader(file, offset, stored)
		side.preview = io.NewSectionReader(file, offset, stored)
		return side, nil
	}
	tail := make([]byte, min(stored, 256))
	if _, err = file.ReadAt(tail, offset+stored-int64(len(tail))); err != nil {
		return nil, err
	}
	hash, preview, err := legacyBodyMarker(tail, stored, expected)
	if err != nil {
		return nil, err
	}
	blob, size, err := t.Blob(hash)
	if err != nil {
		return nil, err
	}
	side.blob = blob
	if size != expected {
		return nil, errors.New("legacy traffic blob is incomplete")
	}
	side.hash, side.body, side.preview = hash, blob, io.NewSectionReader(file, offset, preview)
	return side, nil
}

func credibleLegacyHeader(head string) bool {
	first, _, _ := strings.Cut(head, "\n")
	fields := strings.Fields(first)
	return len(fields) >= 2 && (strings.HasPrefix(fields[0], "HTTP/") || fields[0] == "HTTP" || (len(fields) == 3 && strings.HasPrefix(fields[2], "HTTP/")))
}

// normalizeArchiveSide also recovers old version-1 exports that incorrectly
// placed an entire legacy HTTP file in the header field. Ambiguity fails closed.
func normalizeArchiveSide(head string, body []byte, hash string, expected int) (string, []byte, string, error) {
	if expected < 0 {
		return "", nil, "", errors.New("archived traffic body length is negative")
	}
	parsed, reader, separated, err := splitLegacyEvidence(strings.NewReader(head))
	if err != nil {
		return "", nil, "", err
	}
	if separated {
		remainder, err := io.ReadAll(reader)
		if err != nil {
			return "", nil, "", err
		}
		if len(remainder) > 0 {
			if len(body) > 0 || hash != "" {
				return "", nil, "", errors.New("archived traffic has ambiguous body representations")
			}
			body = remainder
			if len(body) != expected {
				tail := body[max(0, len(body)-256):]
				var preview int64
				hash, preview, err = legacyBodyMarker(tail, int64(len(body)), int64(expected))
				if err != nil {
					return "", nil, "", err
				}
				body = body[:preview]
			}
		}
		head = parsed
	}
	// A partial capture keeps the response's full length in resp_len and stores
	// only the prefix it captured, labelled in the head: an external probe over
	// the capture cap, or a streamed body whose bytes were not all kept. Without
	// that label a short body is corruption, not a partial capture.
	if hash == "" && len(body) != expected && !(len(body) < expected && labelledPartial(head)) {
		return "", nil, "", fmt.Errorf("archived traffic body incomplete: expected %d bytes, read %d", expected, len(body))
	}
	if hash != "" && (!blobHashRe.MatchString(hash) || len(body) > expected) {
		return "", nil, "", errors.New("invalid archived traffic body reference")
	}
	return head, body, hash, nil
}

// labelledPartial reports whether a stored head says its body is not the whole
// response. Both markers keep the declared full length in resp_len, so the
// length alone cannot tell a partial capture from a truncated import.
func labelledPartial(head string) bool {
	return strings.Contains(head, partialMarker) || strings.Contains(head, streamedMarker)
}
