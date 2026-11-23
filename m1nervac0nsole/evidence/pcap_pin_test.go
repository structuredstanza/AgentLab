package evidence

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// frame builds an Ethernet+IPv4+TCP/UDP frame: only the fields the matcher reads.
func frame(src, dst [4]byte, proto byte, sport, dport uint16) []byte {
	f := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:]
	ip[0], ip[9] = 0x45, proto
	copy(ip[12:], src[:])
	copy(ip[16:], dst[:])
	binary.BigEndian.PutUint16(ip[20:], sport)
	binary.BigEndian.PutUint16(ip[22:], dport)
	return f
}

type rec struct {
	ts time.Time
	f  []byte
}

// writePcap writes a classic little-endian microsecond Ethernet pcap.
func writePcap(t *testing.T, path string, recs []rec, mod time.Time) {
	t.Helper()
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], 4)
	binary.LittleEndian.PutUint32(b[16:], 65535)
	binary.LittleEndian.PutUint32(b[20:], 1)
	for _, r := range recs {
		h := make([]byte, 16)
		binary.LittleEndian.PutUint32(h, uint32(r.ts.Unix()))
		binary.LittleEndian.PutUint32(h[4:], uint32(r.ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(h[8:], uint32(len(r.f)))
		binary.LittleEndian.PutUint32(h[12:], uint32(len(r.f)))
		b = append(append(b, h...), r.f...)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func TestPinFlowSelectsOneFlow(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	guest, ssh, smb := [4]byte{10, 98, 0, 2}, [4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 7}
	cap := t.TempDir()
	// Two ring segments, written oldest first; each flow spans both.
	writePcap(t, filepath.Join(cap, "capture.pcap0"), []rec{
		{base, frame(guest, ssh, 6, 40000, 22)},
		{base.Add(time.Second), frame(guest, smb, 6, 40001, 445)},
		{base.Add(2 * time.Second), frame(ssh, guest, 6, 22, 40000)},
	}, base.Add(3*time.Second))
	writePcap(t, filepath.Join(cap, "capture.pcap1"), []rec{
		{base.Add(10 * time.Second), frame(guest, ssh, 6, 40000, 22)},
		{base.Add(11 * time.Second), frame(guest, smb, 17, 40002, 445)},
		{base.Add(100 * time.Second), frame(guest, ssh, 6, 40000, 22)}, // outside the window
	}, base.Add(101*time.Second))
	s := &Store{Dir: t.TempDir()}
	flow := Flow{Host: "10.0.0.5", Port: 22, Proto: "tcp", From: base, To: base.Add(20 * time.Second), CaptureDir: cap, TaskID: 7}

	got, err := s.PinFlow(flow)
	if err != nil {
		t.Fatal(err)
	}
	if got.Packets != 3 || got.Truncated || got.Bytes != 24+3*(16+42) {
		t.Fatalf("pinned %+v, want only the 3 in-window ssh packets", got)
	}
	again, err := s.PinFlow(flow)
	if err != nil || again.SHA256 != got.SHA256 || again.Path != got.Path {
		t.Fatalf("not content addressed: %+v vs %+v (%v)", again, got, err)
	}
	if !strings.HasSuffix(got.Path, got.SHA256+".pcap") {
		t.Fatalf("path %q does not carry the digest", got.Path)
	}
	// The slice is itself a valid capture holding exactly the matched packets.
	raw, err := os.ReadFile(filepath.Join(s.Dir, got.Path))
	if err != nil || int64(len(raw)) != got.Bytes {
		t.Fatalf("slice file: %v len=%d", err, len(raw))
	}
	other := flow
	other.Host, other.Port, other.Proto = "10.0.0.7", 0, "any"
	o, err := s.PinFlow(other)
	if err != nil || o.Packets != 2 || o.SHA256 == got.SHA256 {
		t.Fatalf("other flow: %+v %v", o, err)
	}
	udp := other
	udp.Proto = "udp"
	if u, err := s.PinFlow(udp); err != nil || u.Packets != 1 {
		t.Fatalf("udp only: %+v %v", u, err)
	}
}

func TestPinFlowTruncationAndErrors(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	cap := t.TempDir()
	var recs []rec
	for i := range 5 {
		recs = append(recs, rec{base.Add(time.Duration(i) * time.Second), frame([4]byte{10, 98, 0, 2}, [4]byte{10, 0, 0, 5}, 6, 40000, 22)})
	}
	writePcap(t, filepath.Join(cap, "capture.pcap"), recs, base.Add(10*time.Second))
	s := &Store{Dir: t.TempDir()}
	flow := Flow{Host: "10.0.0.5", From: base, To: base.Add(time.Minute), CaptureDir: cap, TaskID: 7}

	got, err := s.pinFlow(flow, 24+2*(16+42)+5) // room for two whole packets
	if err != nil || got.Packets != 2 || !got.Truncated {
		t.Fatalf("truncation not labelled at the bound: %+v %v", got, err)
	}
	if _, err := s.PinFlow(Flow{Host: "10.0.0.6", From: base, To: base.Add(time.Minute), CaptureDir: cap, TaskID: 7}); err == nil {
		t.Fatal("an empty match must be an error")
	}
	if _, err := s.PinFlow(Flow{Host: "10.0.0.5", From: base, To: base.Add(time.Minute), CaptureDir: t.TempDir(), TaskID: 7}); err == nil {
		t.Fatal("a missing capture must be an error")
	}
	t.Setenv(CaptureDirEnv, "")
	t.Setenv("SSLKEYLOGFILE", "/state/captures/s1/tls/keys.log")
	if d, err := CaptureDir(); err != nil || d != "/state/captures/s1/pcap" {
		t.Fatalf("CaptureDir = %q %v", d, err)
	}
	t.Setenv("SSLKEYLOGFILE", "")
	if _, err := CaptureDir(); err == nil {
		t.Fatal("no configuration must be an error")
	}
}

// A pinned slice lives in the task's findings/<id>/ directory, so the existing
// archive copy and restore carry it with the rest of that task's evidence.
func TestPinnedFlowTravelsWithTaskArchive(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	cap := t.TempDir()
	writePcap(t, filepath.Join(cap, "capture.pcap"), []rec{{base, frame([4]byte{10, 98, 0, 2}, [4]byte{10, 0, 0, 5}, 6, 40000, 22)}}, base.Add(time.Second))
	s := &Store{Dir: t.TempDir()}
	pin, err := s.PinFlow(Flow{Host: "10.0.0.5", From: base, To: base.Add(time.Minute), CaptureDir: cap, TaskID: 7})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("findings", "7", pin.SHA256+".pcap"); pin.Path != want {
		t.Fatalf("path %q, want %q", pin.Path, want)
	}
	pkg := t.TempDir()
	if err := s.CopyFindingEvidence(7, pkg); err != nil {
		t.Fatal(err)
	}
	restored := &Store{Dir: t.TempDir()}
	if err := restored.InstallFindingEvidence(7, pkg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(restored.Dir, pin.Path)); err != nil {
		t.Fatalf("pinned pcap missing after archive round trip: %v", err)
	}
}
