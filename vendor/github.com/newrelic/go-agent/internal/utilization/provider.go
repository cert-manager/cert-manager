package utilization

import (
	"fmt"
	"strings"
	"time"
)

// Helper constants, functions, and types common to multiple providers are
// contained in this file.

// Constants from the spec.
const (
	maxFieldValueSize = 255             // The maximum value size, in bytes.
	providerTimeout   = 1 * time.Second // The maximum time a HTTP provider may block.
	lookupAddrTimeout = 500 * time.Millisecond
)

type validationError struct{ e error }

func (a validationError) Error() string {
	return a.e.Error()
}

func isValidationError(e error) bool {
	_, is := e.(validationError)
	return is
}

// This function normalises string values per the utilization spec.
func normalizeValue(s string) (string, error) {
	out := strings.TrimSpace(s)

	bytes := []byte(out)
	if len(bytes) > maxFieldValueSize {
		return "", validationError{fmt.Errorf("response is too long: got %d; expected <=%d", len(bytes), maxFieldValueSize)}
	}

	for i, r := range out {
		if !isAcceptableRune(r) {
			return "", validationError{fmt.Errorf("bad character %x at position %d in response", r, i)}
		}
	}

	return out, nil
}

func isAcceptableRune(r rune) bool {
	switch r {
	case 0xFFFD:
		return false // invalid UTF-8
	case '_', ' ', '/', '.', '-':
		return true
	default:
		return r > 0x7f || // still allows some invalid UTF-8, but that's the spec.
			('0' <= r && r <= '9') ||
			('a' <= r && r <= 'z') ||
			('A' <= r && r <= 'Z')
	}
}
