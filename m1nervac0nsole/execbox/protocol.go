package execbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

// The supervisor protocol is newline-delimited JSON over one Unix stream
// connection. The first message is a request; a start request may carry file
// descriptors as SCM_RIGHTS (the Chromium CDP pipe). After a start, the same
// connection carries frames in both directions until the process exits.

const (
	opCapabilities = "capabilities"
	opStart        = "start"
	opPublish      = "publish"
	opSetLane      = "set_lane"

	frameReady     = "ready"
	frameStdout    = "stdout"
	frameStderr    = "stderr"
	frameExit      = "exit"
	frameError     = "error"
	frameReport    = "report"
	framePublished = "published"
	frameNotStaged = "not_staged"
	frameLaneSet   = "lane_set"

	frameStdin    = "stdin"
	frameStdinEOF = "stdin_eof"
	frameResize   = "resize"
	frameClose    = "close"
)

// request is the first message on a connection.
type request struct {
	Op      string          `json:"op"`
	Session *sessionWire    `json:"session,omitempty"`
	Spec    *Spec           `json:"spec,omitempty"`
	Publish *publishRequest `json:"publish,omitempty"`
	Lane    *DirectLane     `json:"lane,omitempty"`
}

// publishRequest names the artifact an install session staged for publication.
// The name is one file name inside the session's staging bin directory.
type publishRequest struct {
	Name string `json:"name"`
}

// sessionWire mirrors netpolicy.Session on the wire.
type sessionWire struct {
	ID             string `json:"id"`
	TaskID         int64  `json:"task_id"`
	ConversationID int64  `json:"conversation_id"`
	Purpose        string `json:"purpose"`
	Revision       int64  `json:"revision"`
}

// frame is one message after the request.
type frame struct {
	Type      string     `json:"type"`
	Data      []byte     `json:"data,omitempty"`
	Code      int        `json:"code,omitempty"`
	Message   string     `json:"message,omitempty"`
	Missing   []string   `json:"missing,omitempty"`
	Detail    string     `json:"detail,omitempty"`
	Report    *Report    `json:"report,omitempty"`
	Published *Published `json:"published,omitempty"`
	Handle    string     `json:"handle,omitempty"`
	Rows      int        `json:"rows,omitempty"`
	Cols      int        `json:"cols,omitempty"`
	Signal    string     `json:"signal,omitempty"`
	// Kind tags an error frame the client must turn back into a typed error
	// ("egress"); Detail then names the interface.
	Kind string `json:"kind,omitempty"`
	// StdinAccepted is the byte count the program's stdin pipe accepted, sent on
	// the exit frame. It is a pointer so "accepted zero bytes" and "no exit frame
	// arrived" stay distinguishable.
	StdinAccepted *int64 `json:"stdin_accepted,omitempty"`
}

// wireConn is one protocol connection.
type wireConn struct {
	c *net.UnixConn
	r *bufio.Reader
	// writeMu serialises frames: a session has one goroutine per stream, and a
	// half-written frame would corrupt the stream for every reader.
	writeMu sync.Mutex
}

func newWireConn(c *net.UnixConn) *wireConn {
	return &wireConn{c: c, r: bufio.NewReaderSize(c, 64<<10)}
}

// readFirst reads the opening message and any descriptors sent with it.
func (w *wireConn) readFirst(v any) ([]int, error) {
	buf := make([]byte, 64<<10)
	oob := make([]byte, 4096)
	for {
		n, oobn, _, _, err := w.c.ReadMsgUnix(buf, oob)
		if err != nil {
			return nil, err
		}
		fds, err := parseRights(oob[:oobn])
		if err != nil {
			return nil, err
		}
		if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
			if err := json.Unmarshal(bytes.TrimSpace(buf[:i]), v); err != nil {
				closeFDs(fds)
				return nil, fmt.Errorf("execbox: decode request: %w", err)
			}
			if rest := buf[i+1 : n]; len(rest) > 0 {
				w.r = bufio.NewReaderSize(io.MultiReader(bytes.NewReader(rest), w.c), 64<<10)
			}
			return fds, nil
		}
		// A request larger than one datagram: keep reading without oob.
		var whole bytes.Buffer
		whole.Write(buf[:n])
		for {
			line, err := w.r.ReadBytes('\n')
			whole.Write(line)
			if err == nil {
				break
			}
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if err := json.Unmarshal(bytes.TrimSpace(whole.Bytes()), v); err != nil {
			closeFDs(fds)
			return nil, fmt.Errorf("execbox: decode request: %w", err)
		}
		return fds, nil
	}
}

// read reads one frame.
func (w *wireConn) read(v any) error {
	line, err := w.r.ReadBytes('\n')
	if err != nil {
		return err
	}
	if err := json.Unmarshal(bytes.TrimSpace(line), v); err != nil {
		return fmt.Errorf("execbox: decode frame: %w", err)
	}
	return nil
}

// write sends one message.
func (w *wireConn) write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	_, err = w.c.Write(append(b, '\n'))
	return err
}

// writeWithFDs sends one message with descriptors attached.
func (w *wireConn) writeWithFDs(v any, fds []*os.File) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	rights := make([]int, 0, len(fds))
	for _, f := range fds {
		rights = append(rights, int(f.Fd()))
	}
	oob := syscall.UnixRights(rights...)
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	_, _, err = w.c.WriteMsgUnix(append(b, '\n'), oob, nil)
	return err
}

func parseRights(oob []byte) ([]int, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("execbox: parse control message: %w", err)
	}
	var fds []int
	for _, m := range msgs {
		got, err := syscall.ParseUnixRights(&m)
		if err != nil {
			closeFDs(fds)
			return nil, fmt.Errorf("execbox: parse rights: %w", err)
		}
		fds = append(fds, got...)
	}
	return fds, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}
