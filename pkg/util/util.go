/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"math/rand"
	"net"
	"net/url"
	"sort"
	"time"
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

// Test for equal IP slices even if unsorted
func EqualIPsUnsorted(s1, s2 []net.IP) bool {
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
