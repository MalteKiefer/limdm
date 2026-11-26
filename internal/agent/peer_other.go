//go:build !linux

package agent

import (
	"errors"
	"net"
)

func peerCred(*net.UnixConn) (uint32, int32, error) { return 0, 0, errors.New("peer credentials need Linux") }
