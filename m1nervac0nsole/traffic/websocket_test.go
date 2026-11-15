package traffic

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// exchangeCount is how many exchange rows the store holds.
func exchangeCount(tr *Traffic) int {
	var n int
	tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
	return n
}

// wsOrigin starts a TLS WebSocket origin that hands every accepted connection to
// serve. The recorder reaches it through the gateway hook, which accepts the
// fixture's self-signed certificate through the explicit exception.
func wsOrigin(t *testing.T, serve func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		serve(c)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dialWS opens a WebSocket to the origin through the recorder.
func dialWS(t *testing.T, rec *recorder, srv *httptest.Server, path string) *websocket.Conn {
	t.Helper()
	dialer := &websocket.Dialer{
		Proxy:           func(*http.Request) (*url.URL, error) { return rec.proxy, nil },
		TLSClientConfig: &tls.Config{RootCAs: rec.pool},
	}
	c, _, err := dialer.Dial("wss://localhost:"+portOf(srv.Listener.Addr().String())+path, nil)
	if err != nil {
		t.Fatalf("wss dial through the recorder: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// echoWS echoes every message back with its own type.
func echoWS(c *websocket.Conn) {
	for {
		mt, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		if err := c.WriteMessage(mt, msg); err != nil {
			return
		}
	}
}

// wsHeader is the transcript's first line.
type wsHeader struct {
	V             int    `json:"v"`
	Kind          string `json:"kind"`
	Order         string `json:"order"`
	ControlFrames string `json:"control_frames"`
}

// wsTranscript is one stored WebSocket transcript, decoded.
type wsTranscript struct {
	Header wsHeader
	Frames []wsFrameLine
	Closes []wsCloseLine
	Raw    string
}

// readWSTranscript reads the single stored WebSocket transcript.
func readWSTranscript(t *testing.T, tr *Traffic) wsTranscript {
	t.Helper()
	var blob string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies`).Scan(&blob); err != nil {
		t.Fatalf("reading the transcript blob: %v", err)
	}
	out := wsTranscript{Raw: readBlob(t, tr, blob)}
	lines := strings.Split(strings.TrimSuffix(out.Raw, "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("transcript is empty: %q", out.Raw)
	}
	if err := json.Unmarshal([]byte(lines[0]), &out.Header); err != nil {
		t.Fatalf("transcript header %q: %v", lines[0], err)
	}
	for _, line := range lines[1:] {
		var probe struct {
			Close *wsClose `json:"close"`
		}
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			t.Fatalf("transcript line %q: %v", line, err)
		}
		if probe.Close != nil {
			var cl wsCloseLine
			if err := json.Unmarshal([]byte(line), &cl); err != nil {
				t.Fatalf("transcript close line %q: %v", line, err)
			}
			out.Closes = append(out.Closes, cl)
			continue
		}
		var fr wsFrameLine
		if err := json.Unmarshal([]byte(line), &fr); err != nil {
			t.Fatalf("transcript frame line %q: %v", line, err)
		}
		out.Frames = append(out.Frames, fr)
	}
	return out
}

// wsRowHead is the stored response head of the single WebSocket exchange.
func wsRowHead(t *testing.T, tr *Traffic) string {
	t.Helper()
	var head string
	if err := tr.DB().QueryRow(`SELECT resp_head FROM exchange_bodies`).Scan(&head); err != nil {
		t.Fatalf("reading the response head: %v", err)
	}
	return head
}

// TestWebSocketTranscriptRecordsBothDirections proves every forwarded message is
// persisted with its direction, type and exact bytes, in strictly increasing
// proxy-arrival order, independently of the flow's bounded in-memory retention.
func TestWebSocketTranscriptRecordsBothDirections(t *testing.T) {
	rec := startRecorder(t, newGatewayHook(t))
	c := dialWS(t, rec, wsOrigin(t, echoWS), "/ws")

	// 300 client messages and their 300 echoes: 600 data lines, alternating
	// direction, alternating text and binary.
	const sent = 300
	payloads := make([][]byte, sent)
	types := make([]int, sent)
	for i := range sent {
		if i%2 == 0 {
			types[i] = websocket.TextMessage
			payloads[i] = []byte(fmt.Sprintf("text-%03d", i))
		} else {
			types[i] = websocket.BinaryMessage
			// Invalid UTF-8 on purpose: the transcript must carry bytes, not text.
			payloads[i] = []byte{0xff, 0xfe, byte(i), 0x00, 0x80}
		}
		if err := c.WriteMessage(types[i], payloads[i]); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		mt, got, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if mt != types[i] || !bytes.Equal(got, payloads[i]) {
			t.Fatalf("echo %d = %d %q, want %d %q", i, mt, got, types[i], payloads[i])
		}
	}
	// A close frame from the client, so the session ends by agreement.
	if err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye")); err != nil {
		t.Fatalf("close: %v", err)
	}

	waitFor(t, func() bool { return exchangeCount(rec.tr) == 1 })
	tr := readWSTranscript(t, rec.tr)
	if tr.Header.V != 1 || tr.Header.Kind != "ws-transcript" || tr.Header.Order != "proxy-arrival" || tr.Header.ControlFrames != "not-observable" {
		t.Errorf("transcript header = %+v, want the v1 proxy-arrival header", tr.Header)
	}
	if len(tr.Frames) != 2*sent {
		t.Fatalf("transcript holds %d data lines, want %d", len(tr.Frames), 2*sent)
	}
	var c2s, s2c [][]byte
	for i, fr := range tr.Frames {
		if fr.Seq != int64(i+1) {
			t.Fatalf("frame %d has seq %d, want %d (strictly increasing)", i, fr.Seq, i+1)
		}
		if fr.Len != len(fr.Data) {
			t.Errorf("frame %d len = %d, want %d", i, fr.Len, len(fr.Data))
		}
		want := "text"
		if types[i/2] == websocket.BinaryMessage {
			want = "binary"
		}
		if fr.Type != want {
			t.Errorf("frame %d type = %q, want %q", i, fr.Type, want)
		}
		switch fr.Dir {
		case "c2s":
			c2s = append(c2s, fr.Data)
		case "s2c":
			s2c = append(s2c, fr.Data)
		default:
			t.Fatalf("frame %d dir = %q, want c2s or s2c", i, fr.Dir)
		}
	}
	for _, dir := range []struct {
		name   string
		frames [][]byte
	}{{"c2s", c2s}, {"s2c", s2c}} {
		if len(dir.frames) != sent {
			t.Fatalf("%s holds %d frames, want %d", dir.name, len(dir.frames), sent)
		}
		h := sha256.New()
		want := sha256.New()
		for i := range sent {
			if !bytes.Equal(dir.frames[i], payloads[i]) {
				t.Fatalf("%s frame %d = %q, want %q (send order)", dir.name, i, dir.frames[i], payloads[i])
			}
			h.Write(dir.frames[i])
			want.Write(payloads[i])
		}
		if !bytes.Equal(h.Sum(nil), want.Sum(nil)) {
			t.Errorf("%s payload digest differs from what was sent", dir.name)
		}
	}
	if len(tr.Closes) != 2 {
		t.Fatalf("transcript holds %d close lines, want one per direction: %+v", len(tr.Closes), tr.Closes)
	}
	dirs := map[string]bool{}
	normal := 0
	for _, cl := range tr.Closes {
		dirs[cl.Dir] = true
		if cl.Close.Code == wsCloseNormal {
			normal++
		}
	}
	if !dirs["c2s"] || !dirs["s2c"] || normal != 1 {
		t.Errorf("close lines = %+v, want one per direction with the client's code 1000", tr.Closes)
	}
	// A close frame ended the session, so the row is not labelled partial.
	if head := wsRowHead(t, rec.tr); strings.Contains(head, partialMarker) || strings.Contains(head, streamedMarker) {
		t.Errorf("head = %q, want no capture warning: the whole session was captured", head)
	}
}

// TestWebSocketEndFollowsBothClosures proves WebSocketEnd runs after both
// directions ended, so a recorder finalizing there has seen every frame and both
// closures.
func TestWebSocketEndFollowsBothClosures(t *testing.T) {
	order := &wsOrderAddon{}
	rec := startRecorder(t, newGatewayHook(t), order)
	c := dialWS(t, rec, wsOrigin(t, echoWS), "/ws")
	if err := c.WriteMessage(websocket.TextMessage, []byte("one")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := c.ReadMessage(); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, func() bool { return exchangeCount(rec.tr) == 1 })

	events := order.snapshot()
	if len(events) < 4 {
		t.Fatalf("events = %v, want start, frames, both closes and end", events)
	}
	if events[0] != "start" {
		t.Errorf("first event = %q, want start", events[0])
	}
	if last := events[len(events)-1]; last != "end" {
		t.Errorf("last event = %q, want end", last)
	}
	var closes int
	for _, e := range events {
		if strings.HasPrefix(e, "close-") {
			closes++
		}
	}
	if closes != 2 {
		t.Errorf("events = %v, want exactly two close notifications before end", events)
	}
}

// TestWebSocketOriginKilledIsNotComplete proves a session cut short keeps every
// frame received before the kill, records the error that ended it, and is not
// labelled complete.
func TestWebSocketOriginKilledIsNotComplete(t *testing.T) {
	rec := startRecorder(t, newGatewayHook(t))
	c := dialWS(t, rec, wsOrigin(t, func(c *websocket.Conn) {
		for i := range 3 {
			if err := c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("tick-%d", i))); err != nil {
				return
			}
		}
		// Kill the TCP connection without a close frame.
		c.UnderlyingConn().Close()
	}), "/ws")

	for i := range 3 {
		mt, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if want := fmt.Sprintf("tick-%d", i); mt != websocket.TextMessage || string(msg) != want {
			t.Fatalf("frame %d = %d %q, want %q", i, mt, msg, want)
		}
	}
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("a read succeeded after the origin was killed")
	}

	waitFor(t, func() bool { return exchangeCount(rec.tr) == 1 })
	tr := readWSTranscript(t, rec.tr)
	if len(tr.Frames) != 3 {
		t.Fatalf("transcript holds %d data lines, want the 3 received before the kill", len(tr.Frames))
	}
	if len(tr.Closes) != 2 {
		t.Fatalf("transcript holds %d close lines, want one per direction", len(tr.Closes))
	}
	var withError int
	for _, cl := range tr.Closes {
		if cl.Close.Error != "" {
			withError++
		}
	}
	if withError == 0 {
		t.Errorf("close lines = %+v, want the transport error that ended the session", tr.Closes)
	}
	head := wsRowHead(t, rec.tr)
	if !strings.Contains(head, partialMarker) || !strings.Contains(head, "ended with code") {
		t.Errorf("head = %q, want the partial marker naming the abrupt end", head)
	}
}

// TestWebSocketReserveMidStreamKeepsForwarding proves the capture reserve stops
// only the transcript: both peers still receive every message, and the row keeps
// the counts it captured.
func TestWebSocketReserveMidStreamKeepsForwarding(t *testing.T) {
	const messages = 200
	rec := startRecorder(t, newGatewayHook(t))
	var probes atomic.Int32
	rec.tr.free = func(string) (int64, int64, error) {
		if probes.Add(1) == 1 {
			return 1 << 40, 1 << 40, nil
		}
		return 0, 1 << 40, nil
	}
	c := dialWS(t, rec, wsOrigin(t, echoWS), "/ws")

	payload := bytes.Repeat([]byte("x"), 16<<10)
	for i := range messages {
		if err := c.WriteMessage(websocket.BinaryMessage, payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		mt, got, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if mt != websocket.BinaryMessage || !bytes.Equal(got, payload) {
			t.Fatalf("echo %d did not survive the reserve", i)
		}
	}
	if err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
		t.Fatalf("close: %v", err)
	}

	waitFor(t, func() bool { return exchangeCount(rec.tr) == 1 })
	tr := readWSTranscript(t, rec.tr)
	if len(tr.Frames) >= 2*messages {
		t.Fatalf("transcript holds %d data lines, want capture to have stopped at the reserve", len(tr.Frames))
	}
	if len(tr.Frames) == 0 {
		t.Fatal("no frames were captured before the reserve was reached")
	}
	head := wsRowHead(t, rec.tr)
	if !strings.Contains(head, partialMarker) || !strings.Contains(head, "reserve") {
		t.Errorf("head = %q, want the partial marker naming the reserve", head)
	}
	if !strings.Contains(head, "kept ") || !strings.Contains(head, " of ") {
		t.Errorf("head = %q, want the kept/total counts", head)
	}
}

// TestWebSocketTranscriptSurvivesArchiveRoundTrip proves the transcript is an
// ordinary blob: export, import into an empty store, identical bytes, and a
// resp_len that describes the stored transcript rather than the payload it holds.
func TestWebSocketTranscriptSurvivesArchiveRoundTrip(t *testing.T) {
	rec := startRecorder(t, newGatewayHook(t))
	c := dialWS(t, rec, wsOrigin(t, echoWS), "/ws")
	for i := range 5 {
		msg := []byte(fmt.Sprintf("round-trip-%d", i))
		if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, got, err := c.ReadMessage(); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo %d = %q err=%v", i, got, err)
		}
	}
	if err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, func() bool { return exchangeCount(rec.tr) == 1 })

	var id, blob string
	var respLen int
	if err := rec.tr.DB().QueryRow(`SELECT e.id, b.resp_blob, e.resp_len FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`).Scan(&id, &blob, &respLen); err != nil {
		t.Fatal(err)
	}
	original := readBlob(t, rec.tr, blob)
	if respLen != len(original) {
		t.Fatalf("resp_len = %d, want the transcript's own %d bytes", respLen, len(original))
	}
	// The payload total is not the stored length: the transcript is JSONL.
	if respLen <= 10*len("round-trip-0") {
		t.Fatalf("resp_len = %d, want the transcript bytes rather than the summed payloads", respLen)
	}

	archiveDir := filepath.Join(t.TempDir(), "traffic")
	n, ids, err := rec.tr.ExportTask(1, archiveDir)
	if err != nil || n != 1 || len(ids) != 1 || ids[0] != id {
		t.Fatalf("ExportTask n=%d ids=%v err=%v, want the WebSocket exchange", n, ids, err)
	}
	restored, _ := openTraffic(t)
	if _, err := restored.ImportArchive(archiveDir); err != nil {
		t.Fatalf("ImportArchive: %v", err)
	}
	var gotBlob string
	var gotLen int
	if err := restored.DB().QueryRow(`SELECT b.resp_blob, e.resp_len FROM exchanges e JOIN exchange_bodies b ON b.id = e.id WHERE e.id = ?`, id).Scan(&gotBlob, &gotLen); err != nil {
		t.Fatal(err)
	}
	restoredBytes := readBlob(t, restored, gotBlob)
	if !bytes.Equal([]byte(restoredBytes), []byte(original)) {
		t.Fatal("the restored transcript differs from the exported one")
	}
	if gotLen != len(restoredBytes) {
		t.Errorf("restored resp_len = %d, want the transcript's %d bytes", gotLen, len(restoredBytes))
	}
}

// TestWebSocketRecorderIsOptional proves the message-delivery extension is
// additive: the Addon interface is unchanged, so BaseAddon and LogAddon satisfy
// it as before, and only an addon that opts in is handed frames and closures.
// The vendored web.WebAddon embeds BaseAddon the same way; building the module
// covers it, and it is not imported here because that package embeds the console
// assets.
func TestWebSocketRecorderIsOptional(t *testing.T) {
	var _ mproxy.WebSocketRecorder = (*sink)(nil)
	var _ mproxy.Addon = (*mproxy.LogAddon)(nil)
	var _ mproxy.Addon = (*mproxy.BaseAddon)(nil)
	if _, ok := any(&mproxy.LogAddon{}).(mproxy.WebSocketRecorder); ok {
		t.Error("LogAddon must not have to implement WebSocketRecorder")
	}
	if _, ok := any(&mproxy.BaseAddon{}).(mproxy.WebSocketRecorder); ok {
		t.Error("BaseAddon must not have to implement WebSocketRecorder")
	}
	if _, ok := any(&countingAddon{}).(mproxy.WebSocketRecorder); !ok {
		t.Error("an addon that implements the extension must be handed frames and closures")
	}
}

// wsOrderAddon records the order the WebSocket hooks fire.
type wsOrderAddon struct {
	mproxy.BaseAddon
	mu     sync.Mutex
	events []string
}

func (a *wsOrderAddon) add(event string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
}

func (a *wsOrderAddon) snapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.events...)
}

func (a *wsOrderAddon) WebSocketStart(*mproxy.Flow) { a.add("start") }
func (a *wsOrderAddon) WebSocketFrame(*mproxy.Flow, *mproxy.WebSocketMessage) {
	a.add("frame")
}
func (a *wsOrderAddon) WebSocketClosed(_ *mproxy.Flow, fromClient bool, _ error) {
	if fromClient {
		a.add("close-c2s")
		return
	}
	a.add("close-s2c")
}
func (a *wsOrderAddon) WebSocketEnd(*mproxy.Flow) { a.add("end") }
