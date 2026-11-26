package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Managed files (com.limdm.files) may live below directories a local user
// owns. Every step works on file descriptors opened without following
// symlinks, so swapping a directory for a link between a check and the
// write cannot redirect root's write, chown or removal elsewhere.

// errNotOurs marks a managed file that changed since LiMDM wrote it.
var errNotOurs = errors.New("changed since LiMDM wrote it, left in place")

// openDirNoFollow opens dir by walking from / with O_NOFOLLOW on every
// component. With create, missing directories are made (0755).
func openDirNoFollow(dir string, create bool) (*os.File, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("%s is no clean absolute path", dir)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	cur := "/"
	for _, c := range strings.Split(dir, "/") {
		if c == "" {
			continue
		}
		cur = filepath.Join(cur, c)
		const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		nfd, err := unix.Openat(fd, c, flags, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if err = unix.Mkdirat(fd, c, 0o755); err == nil || errors.Is(err, unix.EEXIST) {
				if nfd, err = unix.Openat(fd, c, flags, 0); err == nil {
					if err = unix.Fchmod(nfd, 0o755); err != nil {
						_ = unix.Close(nfd)
					}
				}
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return nil, fmt.Errorf("%s is a symlink or no directory; declare the real path", cur)
			}
			return nil, err
		}
		fd = nfd
	}
	return os.NewFile(uintptr(fd), dir), nil
}

// openAtNoFollow opens name in dir without following a symlink.
func openAtNoFollow(dir *os.File, name string, flags int, perm uint32) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
	if errors.Is(err, unix.ELOOP) {
		return nil, errors.New("the file is a symlink")
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// regularContent reads an opened file, failing when it is no regular file.
func regularContent(f *os.File) ([]byte, *syscall.Stat_t, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || st == nil {
		return nil, nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<20))
	return b, st, err
}

// writeNoFollow writes path atomically with mode, owner and group, and
// reports whether anything changed. No component of path may be a symlink;
// mode and owner are set on the open file, never through the path.
func writeNoFollow(path string, content []byte, mode os.FileMode, uid, gid int) (bool, error) {
	dir, err := openDirNoFollow(filepath.Dir(path), true)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	base := filepath.Base(path)
	if cur, err := openAtNoFollow(dir, base, unix.O_RDONLY|unix.O_NONBLOCK, 0); err == nil {
		b, st, err := regularContent(cur)
		if err == nil && bytes.Equal(b, content) {
			changed := false
			if os.FileMode(st.Mode).Perm() != mode {
				changed, err = true, cur.Chmod(mode)
			}
			if err == nil && (int(st.Uid) != uid || int(st.Gid) != gid) {
				changed, err = true, cur.Chown(uid, gid)
			}
			cur.Close()
			return changed, err
		}
		cur.Close()
		if err != nil {
			return false, err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	tmpName := ".limdm-" + rand.Text()
	tmp, err := openAtNoFollow(dir, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	_, err = tmp.Write(content)
	err = errors.Join(err, tmp.Chmod(mode), tmp.Chown(uid, gid), tmp.Sync(), tmp.Close())
	if err == nil {
		err = unix.Renameat(int(dir.Fd()), tmpName, int(dir.Fd()), base)
	}
	if err != nil {
		_ = unix.Unlinkat(int(dir.Fd()), tmpName, 0)
		return false, err
	}
	return true, nil
}

// removeNoFollow removes path only when it is a regular file reached
// without symlinks whose content still has the SHA-256 sum LiMDM recorded
// when it wrote it. A missing file is no error; anything else LiMDM did
// not write is errNotOurs.
func removeNoFollow(path, sum string) error {
	notOurs := func(err error) error { return fmt.Errorf("%w (%w)", errNotOurs, err) }
	dir, err := openDirNoFollow(filepath.Dir(path), false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return notOurs(err)
	}
	defer dir.Close()
	base := filepath.Base(path)
	f, err := openAtNoFollow(dir, base, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return notOurs(err)
	}
	b, _, err := regularContent(f)
	f.Close()
	switch {
	case err != nil:
		return notOurs(err)
	case sum == "":
		return notOurs(errors.New("no checksum recorded"))
	case contentSum(b) != sum:
		return notOurs(errors.New("content differs"))
	}
	return unix.Unlinkat(int(dir.Fd()), base, 0)
}

func contentSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
