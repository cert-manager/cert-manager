package cat

import (
	"errors"
	"strconv"
	"strings"
)

// IDHeader represents a decoded cross process ID header (generally encoded as
// a string in the form ACCOUNT#BLOB).
type IDHeader struct {
	AccountID int
	Blob      string
}

var (
	errInvalidAccountID = errors.New("invalid account ID")
)

// NewIDHeader parses the given decoded ID header and creates an IDHeader
// representing it.
func NewIDHeader(in []byte) (*IDHeader, error) {
	parts := strings.Split(string(in), "#")
	if len(parts) != 2 {
		return nil, errUnexpectedArraySize{
			label:    "unexpected number of ID elements",
			expected: 2,
			actual:   len(parts),
		}
	}

	account, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, errInvalidAccountID
	}

	return &IDHeader{
		AccountID: account,
		Blob:      parts[1],
	}, nil
}
