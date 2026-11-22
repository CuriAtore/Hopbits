//go:build !unix

package agent

import "errors"

func execBinary(binaryPath string) error {
	return errors.New("agent: in-place process re-exec requires a Unix host; restart the binary at " + binaryPath)
}
