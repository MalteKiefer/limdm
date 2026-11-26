package agent

import (
	"net"
	"syscall"
)

// peerCred returns the uid and pid of the process on the other end (SO_PEERCRED).
func peerCred(c *net.UnixConn) (uint32, int32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if serr != nil {
		return 0, 0, serr
	}
	return cred.Uid, cred.Pid, nil
}
