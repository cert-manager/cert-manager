package cat

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SyntheticsHeader represents a decoded Synthetics header.
type SyntheticsHeader struct {
	Version    int
	AccountID  int
	ResourceID string
	JobID      string
	MonitorID  string
}

var (
	errInvalidSyntheticsJSON       = errors.New("invalid synthetics JSON")
	errInvalidSyntheticsVersion    = errors.New("version is not a float64")
	errInvalidSyntheticsAccountID  = errors.New("account ID is not a float64")
	errInvalidSyntheticsResourceID = errors.New("synthetics resource ID is not a string")
	errInvalidSyntheticsJobID      = errors.New("synthetics job ID is not a string")
	errInvalidSyntheticsMonitorID  = errors.New("synthetics monitor ID is not a string")
)

type errUnexpectedSyntheticsVersion int

func (e errUnexpectedSyntheticsVersion) Error() string {
	return fmt.Sprintf("unexpected synthetics header version: %d", e)
}

// UnmarshalJSON unmarshalls a SyntheticsHeader from raw JSON.
func (s *SyntheticsHeader) UnmarshalJSON(data []byte) error {
	var ok bool
	var v interface{}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	arr, ok := v.([]interface{})
	if !ok {
		return errInvalidSyntheticsJSON
	}
	if len(arr) != 5 {
		return errUnexpectedArraySize{
			label:    "unexpected number of application data elements",
			expected: 5,
			actual:   len(arr),
		}
	}

	version, ok := arr[0].(float64)
	if !ok {
		return errInvalidSyntheticsVersion
	}
	s.Version = int(version)
	if s.Version != 1 {
		return errUnexpectedSyntheticsVersion(s.Version)
	}

	accountID, ok := arr[1].(float64)
	if !ok {
		return errInvalidSyntheticsAccountID
	}
	s.AccountID = int(accountID)

	if s.ResourceID, ok = arr[2].(string); !ok {
		return errInvalidSyntheticsResourceID
	}

	if s.JobID, ok = arr[3].(string); !ok {
		return errInvalidSyntheticsJobID
	}

	if s.MonitorID, ok = arr[4].(string); !ok {
		return errInvalidSyntheticsMonitorID
	}

	return nil
}
