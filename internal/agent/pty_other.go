//go:build !linux

package agent

import (
	"errors"
	"os"
)

func openPTY() (master, slave *os.File, err error) {
	return nil, nil, errors.New("remote shells need Linux")
}

func setWinsize(*os.File, uint16, uint16) error { return nil }
