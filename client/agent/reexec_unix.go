//go:build unix

package agent

import (
	"os"
	"syscall"
)

func execBinary(binaryPath string) error {
	args := append([]string{binaryPath}, os.Args[1:]...)
	return syscall.Exec(binaryPath, args, os.Environ())
}
