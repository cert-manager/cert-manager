package util

import (
	"testing"
)

func TestEqualUnsorted(t *testing.T) {
	type testT struct {
		desc  string
		s1    []string
		s2    []string
		equal bool
	}
	tests := []testT{
		{
			desc:  "equal but out of order slices should be equal",
			s1:    []string{"a", "b", "c"},
			s2:    []string{"b", "a", "c"},
			equal: true,
		},
		{
			desc:  "non-equal but ordered slices should not be equal",
			s1:    []string{"a", "b"},
			s2:    []string{"a", "b", "c"},
			equal: false,
		},
		{
			desc:  "non-equal but ordered slices should not be equal",
			s1:    []string{"a", "b", "c"},
			s2:    []string{"a", "b"},
			equal: false,
		},
		{
			desc:  "equal and ordered slices should be equal",
			s1:    []string{"a", "b", "c"},
			s2:    []string{"a", "b", "c"},
			equal: true,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := EqualUnsorted(test.s1, test.s2); actual != test.equal {
					t.Errorf("equalUnsorted(%+v, %+v) = %t, but expected %t", test.s1, test.s2, actual, test.equal)
				}
			}
		}(test))
	}
}
