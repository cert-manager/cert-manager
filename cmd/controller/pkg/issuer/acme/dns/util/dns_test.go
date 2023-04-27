// +skip_license_check

package util

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type input struct {
	query   string
	domains []string
}

type test struct {
	name      string
	input     input
	want, got string
}

var domains = []string{
	"foo.example.com",
	"foo.bar.example.com",
	"example.com",
	"baz.com",
}

var tests = []*test{
	{
		name: "TestExactMatchTLD",
		input: input{
			query:   "example.com",
			domains: domains,
		},
		want: "example.com",
	},
	{
		name: "TestExactMatchSubDomain",
		input: input{
			query:   "foo.example.com",
			domains: domains,
		},
		want: "foo.example.com",
	},
	{
		name: "TestExactMatchSubDomainTwoLevels",
		input: input{
			query:   "foo.bar.example.com",
			domains: domains,
		},
		want: "foo.bar.example.com",
	},
	{
		name: "TestPartialMatchTLD",
		input: input{
			query:   "baz.example.com",
			domains: domains,
		},
		want: "example.com",
	},
	{
		name: "TestPartialMatchSubDomain",
		input: input{
			query:   "baz.foo.example.com",
			domains: domains,
		},
		want: "foo.example.com",
	},
	{
		name: "TestNoMatchReversedOrder", // Negative Test Case
		input: input{
			query:   "com.example.foo",
			domains: domains,
		},
		want: "",
	},
	{
		name: "TestNoMatches", // Negative Test Case
		input: input{
			query:   "bar.com",
			domains: domains,
		},
		want: "",
	},
}

func TestLongestMatches(t *testing.T) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.got, _ = FindBestMatch(tc.input.query, tc.input.domains...)
			if tc.got != tc.want {
				assert.Equal(t, tc.want, tc.got, fmt.Sprintf("Failed: TestCase: %s | Query: %s | Want: %v | Got: %v", tc.name, tc.input.query, tc.want, tc.got))
			}
		})
	}
}
