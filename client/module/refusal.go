package module

import (
	"errors"
	"fmt"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

// Refusal is an error that maps to a protocol error code, for JobAck and
// Result.
type Refusal struct {
	Code   nodev1.ErrorCode
	Reason string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("%s: %s", r.Code, r.Reason)
}

// Refuse builds a Refusal.
func Refuse(code nodev1.ErrorCode, format string, args ...any) *Refusal {
	return &Refusal{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// CodeOf returns the error code an error carries, or REFUSED_LOCALLY.
func CodeOf(err error) nodev1.ErrorCode {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY
}
