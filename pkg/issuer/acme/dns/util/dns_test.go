//go:build !livedns_test

// +skip_license_check

package util

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRelatedZone(t *testing.T) {
	tests := []struct {
		name     string
		zone1    string
		zone2    string
		expected bool
	}{
		{
			name:     "same zone",
			zone1:    "example.com.",
			zone2:    "example.com.",
			expected: true,
		},
		{
			name:     "parent/child relationship - zone1 is parent",
			zone1:    "example.com.",
			zone2:    "sub.example.com.",
			expected: true,
		},
		{
			name:     "parent/child relationship - zone2 is parent",
			zone1:    "sub.example.com.",
			zone2:    "example.com.",
			expected: true,
		},
		{
			name:     "sibling zones with common parent",
			zone1:    "foo.example.com.",
			zone2:    "bar.example.com.",
			expected: true,
		},
		{
			name:     "deeply nested sibling zones",
			zone1:    "a.b.example.com.",
			zone2:    "c.d.example.com.",
			expected: true,
		},
		{
			name:     "completely unrelated zones",
			zone1:    "example.com.",
			zone2:    "azure.com.",
			expected: false,
		},
		{
			name:     "wildcard to external zone (azure scenario)",
			zone1:    "example.com.",
			zone2:    "cloudapp.azure.com.",
			expected: false,
		},
		{
			name:     "same TLD but different orgs",
			zone1:    "example.co.uk.",
			zone2:    "other.co.uk.",
			expected: true, // co.uk is shared, matches 2 labels
		},
		{
			name:     "only TLD in common",
			zone1:    "example.com.",
			zone2:    "other.com.",
			expected: false, // only 1 label matches (com)
		},
		{
			name:     "zone1 too short",
			zone1:    "com.",
			zone2:    "example.com.",
			expected: true, // parent/child via IsSubDomain
		},
		{
			name:     "both zones are TLDs",
			zone1:    "com.",
			zone2:    "org.",
			expected: false,
		},
		{
			name:     "three labels matching",
			zone1:    "a.b.example.com.",
			zone2:    "c.b.example.com.",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRelatedZone(tt.zone1, tt.zone2)
			assert.Equal(t, tt.expected, result, "isRelatedZone(%q, %q)", tt.zone1, tt.zone2)
		})
	}
}

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
