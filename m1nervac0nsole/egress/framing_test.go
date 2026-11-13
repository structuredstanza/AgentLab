package egress

import (
	"bufio"
	"strings"
	"testing"
)

// A negative chunk size used to reach make() and panic the whole proxy
// process. strconv.ParseInt accepts a leading sign, so "-1" parsed as -1 and
// the size guard (a plain comparison against maxBody) let it through. This is
// reachable from an untrusted origin's response as well as a client body.
func TestReadChunkedRejectsNegativeSize(t *testing.T) {
	for _, body := range []string{
		"-1\r\nXX\r\n0\r\n\r\n",
		"-7fffffffffffffff\r\n",
	} {
		if _, err := readChunked(bufio.NewReader(strings.NewReader(body))); err == nil {
			t.Errorf("readChunked(%q) accepted a negative chunk size", body)
		}
	}
}

// A huge size overflowed the int addition in the size guard, then panicked on
// the allocation.
func TestReadChunkedRejectsOverflowingSize(t *testing.T) {
	body := "1\r\nX\r\n7fffffffffffffff\r\n"
	if _, err := readChunked(bufio.NewReader(strings.NewReader(body))); err == nil {
		t.Fatal("readChunked accepted a chunk size that overflows the total")
	}
}

// A well-formed chunked body must still decode.
func TestReadChunkedAcceptsValidBody(t *testing.T) {
	body := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	got, err := readChunked(bufio.NewReader(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("valid chunked body rejected: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("decoded %q, want %q", got, "hello world")
	}
}

// Transfer-Encoding wins over Content-Length. Reading at the first header seen
// made "Content-Length: 6" followed by a chunked body consume the framing
// bytes as the body and leave the rest to be parsed as a new request.
func TestReadBodyPrefersTransferEncoding(t *testing.T) {
	body := "5\r\nhello\r\n0\r\n\r\n"
	headers := [][2]string{
		{"Content-Length", "6"},
		{"Transfer-Encoding", "chunked"},
	}
	if _, err := readBody(bufio.NewReader(strings.NewReader(body)), headers); err == nil {
		t.Fatal("readBody accepted both Content-Length and Transfer-Encoding")
	}

	headers = [][2]string{{"Transfer-Encoding", "chunked"}}
	got, err := readBody(bufio.NewReader(strings.NewReader(body)), headers)
	if err != nil {
		t.Fatalf("chunked body rejected: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("decoded %q, want %q", got, "hello")
	}
}

// A plain Content-Length body must still work.
func TestReadBodyContentLength(t *testing.T) {
	got, err := readBody(bufio.NewReader(strings.NewReader("hello!")), [][2]string{{"Content-Length", "6"}})
	if err != nil {
		t.Fatalf("content-length body rejected: %v", err)
	}
	if string(got) != "hello!" {
		t.Fatalf("decoded %q, want %q", got, "hello!")
	}
}

// A body over the cap is refused rather than truncated silently.
func TestReadBodyRejectsOversizedContentLength(t *testing.T) {
	headers := [][2]string{{"Content-Length", "999999999999"}}
	if _, err := readBody(bufio.NewReader(strings.NewReader("")), headers); err == nil {
		t.Fatal("readBody accepted a body above maxBody")
	}
}
