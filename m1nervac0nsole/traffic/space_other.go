//go:build !unix

package traffic

import "errors"

// filesystemSpace is unavailable here, so the capture reserve cannot be measured.
// A probe that cannot measure stops capture with a labelled partial
// (captureSpace): free space that cannot be measured is not free space known to
// exist, and continuing would be an unbounded-capture fallback.
func filesystemSpace(string) (free, total int64, err error) {
	return 0, 0, errors.New("free space is not measurable on this platform")
}
