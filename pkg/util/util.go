/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// genericEqualUnsorted reports whether two slices are identical up to reordering
// using a comparison function.
// If the lengths are different, genericEqualUnsorted returns false. Otherwise, the
// elements are sorted using the comparison function, and the sorted slices are
// compared element by element using the same comparison function. If all elements
// are equal, genericEqualUnsorted returns true. Otherwise it returns false.
func genericEqualUnsorted[S ~[]E, E any](
	s1 S, s2 S,
	cmp func(a, b E) int,
) bool {
	if len(s1) != len(s2) {
		return false
	}

	s1, s2 = slices.Clone(s1), slices.Clone(s2)

	slices.SortStableFunc(s1, cmp)
	slices.SortStableFunc(s2, cmp)

	return slices.EqualFunc(s1, s2, func(a, b E) bool {
		return cmp(a, b) == 0
	})
}

func EqualUnsorted(s1 []string, s2 []string) bool {
	return genericEqualUnsorted(s1, s2, strings.Compare)
}

// Test for equal URL slices even if unsorted. Panics if any element is nil
func EqualURLsUnsorted(s1, s2 []*url.URL) bool {
	return genericEqualUnsorted(s1, s2, func(a, b *url.URL) int {
		return strings.Compare(a.String(), b.String())
	})
}

// Test for equal cmapi.OtherName slices even if unsorted. Panics if any element is nil
func EqualOtherNamesUnsorted(s1, s2 []cmapi.OtherName) bool {
	return genericEqualUnsorted(s1, s2, func(a cmapi.OtherName, b cmapi.OtherName) int {
		if a.OID == b.OID {
			return strings.Compare(a.UTF8Value, b.UTF8Value)
		}
		return strings.Compare(a.OID, b.OID)
	})

}

// EqualIPsUnsorted checks if the given slices of IP addresses contain the same elements, even if in a different order
func EqualIPsUnsorted(s1, s2 []net.IP) bool {
	// Two IPv4 addresses can compare unequal with bytes.Equal which is why net.IP.Equal exists.
	// We still want to sort the lists, though, and we don't want different representations of IPv4 addresses
	// to be sorted differently. That can happen if one is stored as a 4-byte address while
	// the other is stored as a 16-byte representation

	// To avoid ambiguity, we ensure that only the 16-byte form is used for all addresses we work with.
	return genericEqualUnsorted(s1, s2, func(a, b net.IP) int {
		return bytes.Compare(a.To16(), b.To16())
	})
}

// Test for equal KeyUsage slices even if unsorted
func EqualKeyUsagesUnsorted(s1, s2 []cmapi.KeyUsage) bool {
	return genericEqualUnsorted(s1, s2, func(a, b cmapi.KeyUsage) int {
		return strings.Compare(string(a), string(b))
	})
}

// JoinWithEscapeCSV returns the given list as a single line of CSV that
// is escaped with quotes if necessary
func JoinWithEscapeCSV(in []string) (string, error) {
	b := new(bytes.Buffer)
	writer := csv.NewWriter(b)
	if err := writer.Write(in); err != nil {
		return "", fmt.Errorf("failed to write %q as CSV: %w", in, err)
	}
	writer.Flush()

	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("failed to write %q as CSV: %w", in, err)
	}

	s := b.String()
	// CSV writer adds a trailing new line, we need to clean it up
	s = strings.TrimSuffix(s, "\n")
	return s, nil
}

// SplitWithEscapeCSV parses the given input as a single line of CSV, which allows
// a comma-separated list of strings to be parsed while allowing commas to be present
// in each field. For example, a user can specify:
// "10 Downing Street, Westminster",Manchester
// to produce []string{"10 Downing Street, Westminster", "Manchester"}, keeping the comma
// in the first address. Empty lines or multiple CSV records are both rejected.
func SplitWithEscapeCSV(in string) ([]string, error) {
	reader := csv.NewReader(strings.NewReader(in))

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q as CSV: %w", in, err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no values found after parsing %q", in)
	} else if len(records) > 1 {
		return nil, fmt.Errorf("refusing to use %q as input as it parses as multiple lines of CSV", in)
	}

	return records[0], nil
}
