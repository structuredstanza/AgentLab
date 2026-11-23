package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Direct-lane tools (nmap, hydra, ssh, smb, fuzzers) bypass the recording
// proxy, so their traffic exists only in the guest's tcpdump ring. A finding
// that depends on such traffic pins the matching packets here: the ring rotates
// (-C/-W) and would otherwise overwrite the proof before anyone reads it.

// CaptureDirEnv overrides the capture directory (tests, non-guest runs).
const CaptureDirEnv = "M1NERVAC0NSOLE_CAPTURE_PCAP_DIR"

// MaxPinnedFlowBytes bounds one pinned slice. A slice that would exceed it is
// cut at the last whole packet and labelled truncated, never silently clipped.
const MaxPinnedFlowBytes = 64 << 20

// Flow selects packets from the capture: one host (either direction), an
// optional port on either side, a protocol, and a time window.
type Flow struct {
	Host     string    // IP literal; hostnames are resolved by the caller's tools, not here
	Port     int       // 0 = any
	Proto    string    // tcp | udp | any (empty = any)
	From, To time.Time // inclusive
	// CaptureDir overrides CaptureDir() when set.
	CaptureDir string
	// TaskID owns the slice: it lands in the task's findings/<id>/ directory,
	// which archive, export and GC already walk.
	TaskID int64
}

// PinnedFlow describes one content-addressed pcap slice held by the store.
type PinnedFlow struct {
	Path      string `json:"path"` // relative to the evidence dir
	SHA256    string `json:"sha256"`
	Packets   int    `json:"packets"`
	Bytes     int64  `json:"bytes"`
	Truncated bool   `json:"truncated,omitempty"`
}

// CaptureDir returns the pcap ring directory: the explicit override, else the
// sibling of the TLS key log the guest places at <capture>/tls/keys.log.
func CaptureDir() (string, error) {
	if d := os.Getenv(CaptureDirEnv); d != "" {
		return d, nil
	}
	keys := os.Getenv("SSLKEYLOGFILE")
	if keys == "" {
		return "", errors.New("no packet capture configured: neither " + CaptureDirEnv + " nor SSLKEYLOGFILE is set")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(keys)), "pcap"), nil
}

// PinFlow extracts the packets matching f from the capture ring into a
// content-addressed pcap under <Dir>/pcap. The output is a deterministic
// classic pcap (little endian, microsecond), so the same slice hashes the same.
// An absent capture or an empty match is an error: an empty pin would read as
// proof that nothing was sent.
func (s *Store) PinFlow(f Flow) (PinnedFlow, error) {
	return s.pinFlow(f, MaxPinnedFlowBytes)
}

func (s *Store) pinFlow(f Flow, limit int64) (out PinnedFlow, err error) {
	host, err := netip.ParseAddr(f.Host)
	if err != nil {
		return out, fmt.Errorf("flow host %q must be an IP address", f.Host)
	}
	host = host.Unmap()
	var proto byte
	switch strings.ToLower(f.Proto) {
	case "tcp":
		proto = 6
	case "udp":
		proto = 17
	case "", "any":
	default:
		return out, fmt.Errorf("flow proto %q must be tcp, udp or any", f.Proto)
	}
	if f.Port < 0 || f.Port > 65535 {
		return out, fmt.Errorf("flow port %d out of range", f.Port)
	}
	if f.From.IsZero() || f.To.IsZero() || f.To.Before(f.From) {
		return out, errors.New("flow needs a time window with from <= to")
	}
	dir := f.CaptureDir
	if dir == "" {
		if dir, err = CaptureDir(); err != nil {
			return out, err
		}
	}
	segs, err := captureSegments(dir, f.From)
	if err != nil {
		return out, err
	}
	if f.TaskID <= 0 {
		return out, errors.New("flow needs the owning task id")
	}
	pdir := s.findingEvidenceDir(f.TaskID)
	if err = os.MkdirAll(pdir, 0o700); err != nil {
		return out, fmt.Errorf("create pcap dir: %w", err)
	}
	tmp, err := os.CreateTemp(pdir, ".tmp-*")
	if err != nil {
		return out, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	w := bufio.NewWriter(io.MultiWriter(tmp, h))
	m := flowMatch{host: host, port: uint16(f.Port), proto: proto}
	var link, snap uint32
	for _, seg := range segs {
		var stop bool
		link, snap, out, stop, err = copySegment(seg, w, m, f, limit, link, snap, out)
		if err != nil {
			_ = tmp.Close()
			return PinnedFlow{}, err
		}
		if stop {
			break
		}
	}
	if out.Packets == 0 {
		_ = tmp.Close()
		return PinnedFlow{}, fmt.Errorf("no packets matched %s in %s..%s: the ring may have rotated past the window or the tool bypassed the capture",
			f.Host, f.From.Format(time.RFC3339), f.To.Format(time.RFC3339))
	}
	if err = w.Flush(); err != nil {
		_ = tmp.Close()
		return PinnedFlow{}, err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return PinnedFlow{}, err
	}
	if err = tmp.Close(); err != nil {
		return PinnedFlow{}, err
	}
	out.SHA256 = hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(pdir, out.SHA256+".pcap")
	if err = os.Chmod(tmp.Name(), 0o600); err != nil {
		return PinnedFlow{}, err
	}
	if err = os.Rename(tmp.Name(), final); err != nil {
		return PinnedFlow{}, fmt.Errorf("publish pcap slice: %w", err)
	}
	out.Path = s.relPath(final)
	return out, nil
}

// captureSegments lists ring segments oldest first. A segment whose last write
// precedes the window start cannot hold packets from it.
func captureSegments(dir string, from time.Time) ([]string, error) {
	names, err := filepath.Glob(filepath.Join(dir, "capture.pcap*"))
	if err != nil || len(names) == 0 {
		return nil, fmt.Errorf("no packet capture segments under %s", dir)
	}
	type seg struct {
		path string
		mod  time.Time
	}
	var segs []seg
	for _, n := range names {
		fi, err := os.Stat(n)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 || fi.ModTime().Before(from) {
			continue
		}
		segs = append(segs, seg{n, fi.ModTime()})
	}
	sort.Slice(segs, func(i, j int) bool {
		if !segs[i].mod.Equal(segs[j].mod) {
			return segs[i].mod.Before(segs[j].mod)
		}
		return segs[i].path < segs[j].path
	})
	paths := make([]string, len(segs))
	for i, s := range segs {
		paths[i] = s.path
	}
	return paths, nil
}

type flowMatch struct {
	host  netip.Addr
	port  uint16
	proto byte
}

// copySegment appends the matching records of one segment to w. The header is
// written with the first match; a link type that changes between segments is an
// error because one output file carries one link type.
func copySegment(path string, w *bufio.Writer, m flowMatch, f Flow, limit int64, link, snap uint32, out PinnedFlow) (uint32, uint32, PinnedFlow, bool, error) {
	fh, err := os.Open(path)
	if err != nil {
		return link, snap, out, false, err
	}
	defer fh.Close()
	r := bufio.NewReaderSize(fh, 1<<20)
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return link, snap, out, false, nil // segment just created, header not flushed yet
	}
	var bo binary.ByteOrder = binary.LittleEndian
	nano := false
	switch binary.LittleEndian.Uint32(hdr[:4]) {
	case 0xa1b2c3d4:
	case 0xa1b23c4d:
		nano = true
	case 0xd4c3b2a1:
		bo = binary.BigEndian
	case 0x4d3cb2a1:
		bo, nano = binary.BigEndian, true
	default:
		return link, snap, out, false, fmt.Errorf("%s is not a classic pcap file", filepath.Base(path))
	}
	segLink, segSnap := bo.Uint32(hdr[20:]), bo.Uint32(hdr[16:])
	if _, ok := linkHeaderLen[segLink]; !ok {
		return link, snap, out, false, fmt.Errorf("%s: unsupported link type %d", filepath.Base(path), segLink)
	}
	if out.Packets > 0 && segLink != link {
		return link, snap, out, false, fmt.Errorf("%s: link type changed mid-ring", filepath.Base(path))
	}
	var rec [16]byte
	var data []byte
	for {
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			return link, snap, out, false, nil // clean end, or a record still being written
		}
		capLen := bo.Uint32(rec[8:])
		if capLen > 1<<18 {
			return link, snap, out, false, fmt.Errorf("%s: corrupt record length %d", filepath.Base(path), capLen)
		}
		if cap(data) < int(capLen) {
			data = make([]byte, capLen)
		}
		data = data[:capLen]
		if _, err := io.ReadFull(r, data); err != nil {
			return link, snap, out, false, nil
		}
		frac := int64(bo.Uint32(rec[4:]))
		if nano {
			frac /= 1000
		}
		ts := time.Unix(int64(bo.Uint32(rec[:])), frac*1000)
		if ts.Before(f.From) || ts.After(f.To) || !m.match(segLink, data) {
			continue
		}
		if out.Packets == 0 {
			var oh [24]byte
			binary.LittleEndian.PutUint32(oh[0:], 0xa1b2c3d4)
			binary.LittleEndian.PutUint16(oh[4:], 2)
			binary.LittleEndian.PutUint16(oh[6:], 4)
			binary.LittleEndian.PutUint32(oh[16:], segSnap)
			binary.LittleEndian.PutUint32(oh[20:], segLink)
			if _, err := w.Write(oh[:]); err != nil {
				return link, snap, out, false, err
			}
			out.Bytes = 24
			link, snap = segLink, segSnap
		}
		if out.Bytes+16+int64(capLen) > limit {
			out.Truncated = true
			return link, snap, out, true, nil
		}
		var oh [16]byte
		binary.LittleEndian.PutUint32(oh[0:], bo.Uint32(rec[:]))
		binary.LittleEndian.PutUint32(oh[4:], uint32(frac))
		binary.LittleEndian.PutUint32(oh[8:], capLen)
		binary.LittleEndian.PutUint32(oh[12:], bo.Uint32(rec[12:]))
		if _, err := w.Write(oh[:]); err != nil {
			return link, snap, out, false, err
		}
		if _, err := w.Write(data); err != nil {
			return link, snap, out, false, err
		}
		out.Bytes += 16 + int64(capLen)
		out.Packets++
	}
}

// linkHeaderLen maps the pcap link types the guest capture can produce
// (tcpdump -i any is Linux cooked v1/v2) to their link header size.
var linkHeaderLen = map[uint32]int{1: 14, 101: 0, 113: 16, 276: 20}

// match reports whether the frame is IP traffic of the flow.
// shortcut: IPv6 extension headers are not walked, so a flow carried behind
// one is missed; add the walk if direct-lane tools start emitting them.
func (m flowMatch) match(link uint32, frame []byte) bool {
	off := linkHeaderLen[link]
	if len(frame) <= off {
		return false
	}
	ip := frame[off:]
	var src, dst netip.Addr
	var proto byte
	var l4 []byte
	switch ip[0] >> 4 {
	case 4:
		ihl := int(ip[0]&15) * 4
		if len(ip) < 20 || ihl < 20 || len(ip) < ihl {
			return false
		}
		src, dst, proto = netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20])), ip[9]
		if (uint16(ip[6]&0x1f)<<8 | uint16(ip[7])) == 0 { // later fragments carry no ports
			l4 = ip[ihl:]
		}
	case 6:
		if len(ip) < 40 {
			return false
		}
		src, dst, proto = netip.AddrFrom16([16]byte(ip[8:24])), netip.AddrFrom16([16]byte(ip[24:40])), ip[6]
		l4 = ip[40:]
	default:
		return false
	}
	if src.Unmap() != m.host && dst.Unmap() != m.host {
		return false
	}
	if m.proto != 0 && proto != m.proto {
		return false
	}
	if m.port == 0 {
		return true
	}
	if (proto != 6 && proto != 17) || len(l4) < 4 {
		return false
	}
	return binary.BigEndian.Uint16(l4) == m.port || binary.BigEndian.Uint16(l4[2:]) == m.port
}
