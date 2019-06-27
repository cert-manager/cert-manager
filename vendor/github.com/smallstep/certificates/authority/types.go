package authority

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// multiString represents a type that can be encoded/decoded in JSON as a single
// string or an array of strings.
type multiString []string

// First returns the first element of a multiString. It will return an empty
// string if the multistring is empty.
func (s multiString) First() string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// HasEmpties returns `true` if any string in the array is empty.
func (s multiString) HasEmpties() bool {
	if len(s) == 0 {
		return true
	}
	for _, ss := range s {
		if len(ss) == 0 {
			return true
		}
	}
	return false
}

// MarshalJSON marshals the multistring as a string or a slice of strings . With
// 0 elements it will return the empty string, with 1 element a regular string,
// otherwise a slice of strings.
func (s multiString) MarshalJSON() ([]byte, error) {
	switch len(s) {
	case 0:
		return []byte(`""`), nil
	case 1:
		return json.Marshal(s[0])
	default:
		return json.Marshal([]string(s))
	}
}

// UnmarshalJSON parses a string or a slice and sets it to the multiString.
func (s *multiString) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("multiString cannot be nil")
	}
	if len(data) == 0 {
		*s = nil
		return nil
	}
	// Parse string
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return errors.Wrapf(err, "error unmarshalling %s", data)
		}
		*s = []string{str}
		return nil
	}
	// Parse array
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return errors.Wrapf(err, "error unmarshalling %s", data)
	}
	*s = ss
	return nil
}
