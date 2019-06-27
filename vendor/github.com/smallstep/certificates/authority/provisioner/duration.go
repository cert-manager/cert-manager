package provisioner

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

// Duration is a wrapper around Time.Duration to aid with marshal/unmarshal.
type Duration struct {
	time.Duration
}

// NewDuration parses a duration string and returns a Duration type or an error
// if the given string is not a duration.
func NewDuration(s string) (*Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s as duration", s)
	}
	return &Duration{Duration: d}, nil
}

// MarshalJSON parses a duration string and sets it to the duration.
//
// A duration string is a possibly signed sequence of decimal numbers, each with
// optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func (d *Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

// UnmarshalJSON parses a duration string and sets it to the duration.
//
// A duration string is a possibly signed sequence of decimal numbers, each with
// optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func (d *Duration) UnmarshalJSON(data []byte) (err error) {
	var (
		s  string
		dd time.Duration
	)
	if d == nil {
		return errors.New("duration cannot be nil")
	}
	if err = json.Unmarshal(data, &s); err != nil {
		return errors.Wrapf(err, "error unmarshaling %s", data)
	}
	if dd, err = time.ParseDuration(s); err != nil {
		return errors.Wrapf(err, "error parsing %s as duration", s)
	}
	d.Duration = dd
	return
}

// Value returns 0 if the duration is null, the inner duration otherwise.
func (d *Duration) Value() time.Duration {
	if d == nil {
		return 0
	}
	return d.Duration
}
