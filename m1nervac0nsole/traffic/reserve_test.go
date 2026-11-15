package traffic

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestCaptureReserveComesFromTheEnvironment proves the deployed lab has one
// authority for the capture reserve: the numbers guest-start.py passes decide the
// floor this recorder keeps free, and the threshold writers check is that floor.
func TestCaptureReserveComesFromTheEnvironment(t *testing.T) {
	t.Setenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_MB", "4096")
	t.Setenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_PCT", "50")
	tr, _ := openTraffic(t)
	if tr.reserveFloor != 4096<<20 || tr.reservePct != 50 {
		t.Fatalf("reserve = %d MiB / %d%%, want 4096 MiB / 50%%", tr.reserveFloor>>20, tr.reservePct)
	}
	// 50% of 8 GiB is exactly the floor; 50% of 200 GiB is the share.
	if got, want := tr.reserveBytes(8192<<20), int64(4096<<20); got != want {
		t.Errorf("reserve on an 8 GiB volume = %d MiB, want %d MiB", got>>20, want>>20)
	}
	if got, want := tr.reserveBytes(200<<30), int64(100<<30); got != want {
		t.Errorf("reserve on a 200 GiB volume = %d MiB, want %d MiB", got>>20, want>>20)
	}

	tr.free = func(string) (int64, int64, error) { return 4095 << 20, 8192 << 20, nil }
	reason := tr.captureSpace(streamCheckBytes)
	if !strings.Contains(reason, "reserve reached") || !strings.Contains(reason, "4096 MiB") {
		t.Errorf("captureSpace below the configured reserve = %q, want the reserve reason", reason)
	}
	// The decision is store-wide: a later writer stops for the same reason
	// instead of probing a filesystem that is already at its floor.
	if again := tr.captureSpace(1); again != reason {
		t.Errorf("second captureSpace = %q, want the latched %q", again, reason)
	}
}

// TestUnusableReserveEnvFallsBackToTheStandaloneDefault proves an unusable value
// keeps the guard rather than disabling it, and that the defaults are what a run
// outside the lab uses.
func TestUnusableReserveEnvFallsBackToTheStandaloneDefault(t *testing.T) {
	t.Setenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_MB", "not-a-number")
	t.Setenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_PCT", "0")
	if floor, pct := captureReserve(); floor != captureReserveFloorBytes || pct != captureReservePct {
		t.Fatalf("reserve = %d MiB / %d%%, want the standalone %d MiB / %d%%",
			floor>>20, pct, captureReserveFloorBytes>>20, captureReservePct)
	}
	// Unset is the same as unusable: the defaults stand.
	t.Setenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_MB", "")
	t.Setenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_PCT", "")
	if floor, pct := captureReserve(); floor != captureReserveFloorBytes || pct != captureReservePct {
		t.Fatalf("unset reserve = %d MiB / %d%%, want the standalone defaults", floor>>20, pct)
	}
}

// TestUnmeasurableFilesystemStopsCapture proves a probe error is not an implicit
// unbounded-capture fallback: spooling stops with a labelled partial, the client
// still receives every byte, and the metadata row is still written.
func TestUnmeasurableFilesystemStopsCapture(t *testing.T) {
	const size = 6 << 20
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.Write(payload)
	}))
	defer srv.Close()

	rec := startRecorder(t, newGatewayHook(t))
	// Room for the first check, then the probe fails: a real unmeasurable
	// filesystem with a prefix already captured.
	var probes atomic.Int32
	rec.tr.free = func(string) (int64, int64, error) {
		if probes.Add(1) == 1 {
			return 1 << 40, 1 << 40, nil
		}
		return 0, 0, errors.New("statfs is not available")
	}

	res, err := rec.client.Get(originURL(srv) + "/big")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("the client received %d bytes, want the whole %d", len(body), size)
	}

	waitFor(t, func() bool { return exchangeCount(rec.tr) == 1 })
	var head, blob string
	var respLen int
	if err := rec.tr.DB().QueryRow(`SELECT b.resp_head, b.resp_blob, e.resp_len FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`).Scan(&head, &blob, &respLen); err != nil {
		t.Fatal(err)
	}
	if respLen != size {
		t.Errorf("recorded response length = %d, want the full %d", respLen, size)
	}
	if !strings.Contains(head, partialMarker) || !strings.Contains(head, "unmeasurable") {
		t.Errorf("head = %q, want the partial marker naming the unmeasurable filesystem", head)
	}
	stored := readBlob(t, rec.tr, blob)
	if len(stored) == 0 || len(stored) >= size {
		t.Fatalf("stored prefix = %d bytes, want a partial body", len(stored))
	}
	if !bytes.Equal([]byte(stored), payload[:len(stored)]) {
		t.Error("the stored prefix is not the start of the body")
	}
}

// TestBufferedBodyOverReserveKeepsPreviewOnly proves the buffered blob-spill path
// record() uses stops at the same reserve: the preview stays inline, no blob is
// written, and the row says its body is a prefix instead of reading as whole.
func TestBufferedBodyOverReserveKeepsPreviewOnly(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.free = func(string) (int64, int64, error) { return 0, 1 << 40, nil }

	// Above maxInlineBody so it spills, below the proxy's 5 MiB stream threshold
	// so record() buffers it.
	body := bytes.Repeat([]byte("x"), 300<<10)
	tr.record(newFlow("big.example.com", "GET", "/big", nil, body, withRespType("text/plain")))

	var head string
	var blob sql.NullString
	var inline []byte
	var respLen int
	if err := tr.DB().QueryRow(`SELECT b.resp_head, b.resp_blob, b.resp_body, e.resp_len FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`).Scan(&head, &blob, &inline, &respLen); err != nil {
		t.Fatal(err)
	}
	if blob.Valid {
		t.Errorf("a blob was written at the reserve: %q", blob.String)
	}
	if respLen != len(body) {
		t.Errorf("resp_len = %d, want the full %d", respLen, len(body))
	}
	if len(inline) != blobPreview {
		t.Errorf("inline preview = %d bytes, want %d", len(inline), blobPreview)
	}
	if !strings.Contains(head, partialMarker) || !strings.Contains(head, "response body") || !strings.Contains(head, "reserve") {
		t.Errorf("head = %q, want the partial marker naming the response body and the reserve", head)
	}
}

// TestStreamWriteFailureIsLabelled proves a write failure (ENOSPC, or a short
// write, which os.File reports the same way) stops the spool with the reason and
// leaves a row that says what was kept.
func TestStreamWriteFailureIsLabelled(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("/dev/full is not available: %v", err)
	}
	defer full.Close()

	tr, _ := openTraffic(t)
	payload := []byte("payload the capture could not keep")
	sp := &streamSpool{
		t:    tr,
		f:    newFlow("write.example.com", "GET", "/x", nil, nil),
		sum:  sha256.New(),
		file: full,
		n:    int64(len(payload)),
		eof:  true,
	}
	sp.write(payload)
	if !strings.Contains(sp.stopped, "writing the capture failed") {
		t.Fatalf("stopped = %q, want the write failure", sp.stopped)
	}
	if sp.kept != 0 {
		t.Errorf("kept = %d bytes, want 0", sp.kept)
	}

	sp.finish()
	var head string
	var respLen int
	if err := tr.DB().QueryRow(`SELECT b.resp_head, e.resp_len FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`).Scan(&head, &respLen); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(head, partialMarker) || !strings.Contains(head, "writing the capture failed") {
		t.Errorf("head = %q, want the partial marker naming the write failure", head)
	}
	if respLen != len(payload) {
		t.Errorf("resp_len = %d, want what the client received (%d)", respLen, len(payload))
	}
}

// TestConcurrentStreamsBoundedAfterReserveFlip proves the store-wide counter and
// the latched decision bound concurrent overshoot: once the probe reports the
// reserve, every writer stops at its next check, so the bytes retained after the
// flip are about one check interval per writer rather than a whole body each.
func TestConcurrentStreamsBoundedAfterReserveFlip(t *testing.T) {
	const (
		streams = 32
		size    = 6 << 20
	)
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.Write(payload)
	}))
	defer srv.Close()

	rec := startRecorder(t, newGatewayHook(t))
	// The first probe sees room, every later one sees the reserve: a real flip
	// without filling a disk.
	var probes atomic.Int32
	rec.tr.free = func(string) (int64, int64, error) {
		if probes.Add(1) == 1 {
			return 1 << 40, 1 << 40, nil
		}
		return 0, 1 << 40, nil
	}

	var wg sync.WaitGroup
	for range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := rec.client.Get(originURL(srv) + "/big")
			if err != nil {
				t.Errorf("GET: %v", err)
				return
			}
			defer res.Body.Close()
			n, err := io.Copy(io.Discard, res.Body)
			if err != nil || n != size {
				t.Errorf("client received %d bytes (err=%v), want %d", n, err, size)
			}
		}()
	}
	wg.Wait()

	waitFor(t, func() bool { return exchangeCount(rec.tr) == streams })
	rows, err := rec.tr.DB().Query(`SELECT b.resp_head, COALESCE(b.resp_blob, '') FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var total int64
	for rows.Next() {
		var head, blob string
		if err := rows.Scan(&head, &blob); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(head, partialMarker) {
			t.Errorf("row head = %q, want the partial marker", head)
		}
		if blob == "" {
			continue
		}
		f, n, err := rec.tr.Blob(blob)
		if err != nil {
			t.Fatalf("opening blob %s: %v", blob, err)
		}
		f.Close()
		total += n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// One check interval plus a read per writer, plus the interval the first
	// (under-reserve) probe allowed.
	limit := int64(streams*(streamCheckBytes+64<<10)) + streamCheckBytes
	if total > limit {
		t.Errorf("stored %d bytes after the reserve flip, want at most %d", total, limit)
	}
	if total == 0 {
		t.Error("nothing was captured before the reserve was reached")
	}
}
