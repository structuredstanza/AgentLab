//go:build unix

package traffic

import "syscall"

// filesystemSpace reports the free and total bytes of the filesystem holding
// dir. Free is what an unprivileged writer can still use (f_bavail), which is
// the number the capture reserve is about.
func filesystemSpace(dir string) (free, total int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	bs := int64(st.Bsize)
	return int64(st.Bavail) * bs, int64(st.Blocks) * bs, nil
}
