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
	"math/rand"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"golang.org/x/exp/slices"
)

func OnlyOneNotNil(items ...interface{}) (any bool, one bool) {
	oneNotNil := false
	for _, i := range items {
		if i != nil {
			if oneNotNil {
				return true, false
			}
			oneNotNil = true
		}
	}
	return oneNotNil, oneNotNil
}

func EqualSorted(s1, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}

	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}

	return true
}

func EqualUnsorted(s1 []string, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}
	s1_2, s2_2 := make([]string, len(s1)), make([]string, len(s2))
	copy(s1_2, s1)
	copy(s2_2, s2)
	sort.Strings(s1_2)
	sort.Strings(s2_2)
	for i, s := range s1_2 {
		if s != s2_2[i] {
			return false
		}
	}
	return true
}

// Test for equal URL slices even if unsorted. Panics if any element is nil
func EqualURLsUnsorted(s1, s2 []*url.URL) bool {
	if len(s1) != len(s2) {
		return false
	}
	s1_2, s2_2 := make([]*url.URL, len(s1)), make([]*url.URL, len(s2))
	copy(s1_2, s1)
	copy(s2_2, s2)

	sort.SliceStable(s1_2, func(i, j int) bool {
		return s1_2[i].String() < s1_2[j].String()
	})
	sort.SliceStable(s2_2, func(i, j int) bool {
		return s2_2[i].String() < s2_2[j].String()
	})

	for i, s := range s1_2 {
		if s.String() != s2_2[i].String() {
			return false
		}
	}
	return true
}

// EqualIPsUnsorted checks if the given slices of IP addresses contain the same elements, even if in a different order
func EqualIPsUnsorted(s1, s2 []net.IP) bool {
	if len(s1) != len(s2) {
		return false
	}

	// Two IPv4 addresses can compare unequal with bytes.Equal which is why net.IP.Equal exists.
	// We still want to sort the lists, though, and we don't want different representations of IPv4 addresses
	// to be sorted differently. That can happen if one is stored as a 4-byte address while
	// the other is stored as a 16-byte representation

	// To avoid ambiguity, we ensure that only the 16-byte form is used for all addresses we work with.

	s1_2, s2_2 := make([]net.IP, len(s1)), make([]net.IP, len(s2))

	for i := 0; i < len(s1); i++ {
		s1_2[i] = s1[i].To16()
		s2_2[i] = s2[i].To16()
	}

	slices.SortFunc(s1_2, func(a net.IP, b net.IP) int {
		return bytes.Compare([]byte(a), []byte(b))
	})

	slices.SortFunc(s2_2, func(a net.IP, b net.IP) int {
		return bytes.Compare([]byte(a), []byte(b))
	})

	return slices.EqualFunc(s1_2, s2_2, func(a net.IP, b net.IP) bool {
		return a.Equal(b)
	})
}

// Test for equal KeyUsage slices even if unsorted
func EqualKeyUsagesUnsorted(s1, s2 []cmapi.KeyUsage) bool {
	if len(s1) != len(s2) {
		return false
	}
	s1_2, s2_2 := make([]string, len(s1)), make([]string, len(s2))
	// we may want to implement a sort interface here instead of []byte conversion
	for i := range s1 {
		s1_2[i] = string(s1[i])
		s2_2[i] = string(s2[i])
	}

	sort.SliceStable(s1_2, func(i, j int) bool {
		return s1_2[i] < s1_2[j]
	})
	sort.SliceStable(s2_2, func(i, j int) bool {
		return s2_2[i] < s2_2[j]
	})

	for i, s := range s1_2 {
		if s != s2_2[i] {
			return false
		}
	}
	return true
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// Contains returns true if a string is contained in a string slice
func Contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// Subset returns true if one slice is an unsorted subset of the first.
func Subset(set, subset []string) bool {
	for _, s := range subset {
		if !Contains(set, s) {
			return false
		}
	}

	return true
}

// JoinWithEscapeCSV returns the given list as a single line of CSV that
// is escaped with quotes if necessary
func JoinWithEscapeCSV(in []string) (string, error) {
	b := new(bytes.Buffer)
	writer := csv.NewWriter(b)
	writer.Write(in)
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
