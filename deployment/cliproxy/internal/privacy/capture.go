package privacy

import (
	"bytes"
	"errors"
	"io"

	"github.com/artex/cliproxyhost/internal/contract"
)

// Direction says which side of an inference exchange a Record holds.
type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
)

// Record is one captured inference body.
type Record struct {
	Direction       Direction
	Provider        contract.Provider
	Model           string
	Profile         contract.ProfileID
	SessionID       string
	Path            string
	ContentType     string
	ContentEncoding string
	Body            []byte
	Complete        bool
	Truncated       bool
}

// Sink persists captures. Record must copy Body before returning if it keeps it.
type Sink interface {
	Record(Record) error
}

var errCapture = errors.New("capture failed")

// captureBody tees a response body into a bounded buffer and records it once,
// on EOF or Close.
type captureBody struct {
	rc   io.ReadCloser
	sink Sink
	rec  Record
	buf  bytes.Buffer
	done bool
}

func newCaptureBody(rc io.ReadCloser, sink Sink, rec Record) *captureBody {
	return &captureBody{rc: rc, sink: sink, rec: rec}
}

func (c *captureBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if !c.done {
		c.keep(p[:n])
	}
	if err == nil || c.done {
		return n, err
	}
	if ferr := c.finish(err == io.EOF); ferr != nil {
		return n, ferr
	}
	return n, err
}

func (c *captureBody) Close() error {
	ferr := c.finish(false)
	cerr := c.rc.Close()
	if ferr != nil {
		return ferr
	}
	return cerr
}

func (c *captureBody) keep(b []byte) {
	room := maxInferenceBody - c.buf.Len()
	if len(b) > room {
		b = b[:room]
		c.rec.Truncated = true
	}
	c.buf.Write(b)
}

func (c *captureBody) finish(complete bool) error {
	if c.done {
		return nil
	}
	c.done = true
	c.rec.Body = c.buf.Bytes()
	c.rec.Complete = complete
	if err := c.sink.Record(c.rec); err != nil {
		return errCapture
	}
	return nil
}
