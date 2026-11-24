package server

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	gbkencoding "golang.org/x/text/encoding/simplifiedchinese"
)

// Go's archive/zip provides Store and Deflate. We also support bzip2 and
// zstd. For unsupported methods and encrypted entries, give guidance before
// attempting decompression rather than returning the generic ZIP error.
const (
	zipMethodStore     = 0
	zipMethodDeflate   = 8
	zipMethodDeflate64 = 9
	zipMethodBzip2     = 12
	zipMethodLZMA      = 14
	zipMethodZstdPKW   = 20 // The number PKWARE initially assigned to zstd
	zipMethodZstd      = 93
	zipMethodXZ        = 95
	zipMethodJPEG      = 96
	zipMethodWavPack   = 97
	zipMethodPPMd      = 98
	zipMethodAES       = 99
)

var zipMethodNames = map[uint16]string{
	zipMethodStore:     "Store",
	zipMethodDeflate:   "Deflate",
	zipMethodDeflate64: "Deflate64",
	zipMethodBzip2:     "bzip2",
	zipMethodLZMA:      "LZMA",
	zipMethodZstdPKW:   "Zstandard",
	zipMethodZstd:      "Zstandard",
	zipMethodXZ:        "XZ",
	zipMethodJPEG:      "JPEG",
	zipMethodWavPack:   "WavPack",
	zipMethodPPMd:      "PPMd",
	zipMethodAES:       "AES encryption",
}

// User-facing error response text for skill upload failures. fsUploadSkill
// passes it through as-is via writeErr(400, err.Error()) (server_mgmt.go).
const (
	errSkillZipParse       = "Failed to parse the archive file (must be zip format): %w"
	errSkillZipEncrypted   = "The archive is encrypted (%s). Please upload an unencrypted zip file."
	errSkillZipUnsupported = "Unsupported compression method: %s (method %d), file %s. " +
		"Recompress with the 'Store' or 'Deflate' method " +
		"(in 7-Zip or WinRAR, select Deflate as the compression method, or use the operating system's built-in compression or the command-line zip -r)."
)

func zipMethodName(m uint16) string {
	if n, ok := zipMethodNames[m]; ok {
		return n
	}
	return "Unknown"
}

// newSkillZipReader parses an uploaded archive and registers the extra decompressors
// we can support beyond the stdlib's Store/Deflate.
func newSkillZipReader(buf []byte) (*zip.Reader, error) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return nil, fmt.Errorf(errSkillZipParse, err)
	}
	zr.RegisterDecompressor(zipMethodBzip2, func(r io.Reader) io.ReadCloser {
		return io.NopCloser(bzip2.NewReader(r))
	})
	zdec := zstd.ZipDecompressor(zstd.WithDecoderConcurrency(1))
	zr.RegisterDecompressor(zipMethodZstd, zdec)
	zr.RegisterDecompressor(zipMethodZstdPKW, zdec)
	return zr, nil
}

// skillZipEntry pairs a zip entry with its decoded (UTF-8) name — f.Name may hold
// raw GBK bytes, see zipEntryName.
type skillZipEntry struct {
	f    *zip.File
	name string
}

// skillZipEntries lists the archive's real files (no directory entries, no archiver
// junk) with their names decoded to UTF-8.
func skillZipEntries(zr *zip.Reader) []skillZipEntry {
	out := make([]skillZipEntry, 0, len(zr.File))
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := zipEntryName(f)
		if strings.HasPrefix(name, "__MACOSX/") || strings.Contains(name, "/__MACOSX/") ||
			path.Base(name) == ".DS_Store" {
			continue // Leftover entries left behind by macOS when it creates a compressed archive
		}
		out = append(out, skillZipEntry{f: f, name: name})
	}
	return out
}

// zipEntryName returns the entry path as UTF-8. Some archivers write GBK
// names without the UTF-8 flag; Go preserves those bytes, so decode them
// before path validation.
func zipEntryName(f *zip.File) string {
	if utf8.ValidString(f.Name) {
		return f.Name
	}
	if dec, err := gbkencoding.GBK.NewDecoder().String(f.Name); err == nil && utf8.ValidString(dec) {
		return dec
	}
	return f.Name
}

// checkSkillZipMethods rejects archives we cannot extract, naming the offending
// entry and method instead of letting f.Open() fail with an opaque English error.
func checkSkillZipMethods(entries []skillZipEntry) error {
	for _, e := range entries {
		if e.f.Flags&0x1 != 0 || e.f.Method == zipMethodAES {
			return fmt.Errorf(errSkillZipEncrypted, e.name)
		}
		switch e.f.Method {
		case zipMethodStore, zipMethodDeflate, zipMethodBzip2, zipMethodZstd, zipMethodZstdPKW:
		default:
			return fmt.Errorf(errSkillZipUnsupported,
				zipMethodName(e.f.Method), e.f.Method, e.name)
		}
	}
	return nil
}
