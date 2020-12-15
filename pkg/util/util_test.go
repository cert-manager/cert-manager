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
	"net"
	"net/url"
	"testing"
)

type testT struct {
	desc  string
	s1    []string
	s2    []string
	equal bool
}

var stringSliceTestData = []testT{
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
	{
		desc:  "unequal lists of the same length are not equal",
		s1:    []string{"example.com"},
		s2:    []string{"notexample.com"},
		equal: false,
	},
}

func TestEqualUnsorted(t *testing.T) {
	for _, test := range stringSliceTestData {
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := EqualUnsorted(test.s1, test.s2); actual != test.equal {
					t.Errorf("equalUnsorted(%+v, %+v) = %t, but expected %t", test.s1, test.s2, actual, test.equal)
				}
			}
		}(test))
	}
}

func TestEqualURLsUnsorted(t *testing.T) {
	for _, test := range stringSliceTestData {
		s1, s2 := parseURLs(t, test.s1), parseURLs(t, test.s2)
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := EqualURLsUnsorted(s1, s2); actual != test.equal {
					t.Errorf("equalURLsUnsorted(%+v, %+v) = %t, but expected %t", s1, s2, actual, test.equal)
				}
			}
		}(test))
	}
}

func TestEqualIPsUnsorted(t *testing.T) {
	for _, test := range stringSliceTestData {
		s1, s2 := parseIPs(t, test.s1), parseIPs(t, test.s2)
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := EqualIPsUnsorted(s1, s2); actual != test.equal {
					t.Errorf("equalIpsUnsorted(%+v, %+v) = %t, but expected %t", s1, s2, actual, test.equal)
				}
			}
		}(test))
	}
}

func TestContains(t *testing.T) {
	type testT struct {
		desc  string
		slice []string
		value string
		equal bool
	}
	tests := []testT{
		{
			desc:  "slice containing value",
			slice: []string{"a", "b", "c"},
			value: "a",
			equal: true,
		},
		{
			desc:  "slice not containing value",
			slice: []string{"a", "b", "c"},
			value: "x",
			equal: false,
		},
		{
			desc:  "empty slice",
			slice: []string{},
			value: "x",
			equal: false,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := Contains(test.slice, test.value); actual != test.equal {
					t.Errorf("Contains(%+v, %+v) = %t, but expected %t", test.slice, test.value, actual, test.equal)
				}
			}
		}(test))
	}
}

func parseURLs(t *testing.T, urlStrs []string) []*url.URL {
	var urls []*url.URL

	for _, u := range urlStrs {
		url, err := url.Parse(u)
		if err != nil {
			t.Errorf("failed to parse url %s: %s", u, err)
			t.FailNow()
		}

		urls = append(urls, url)
	}

	return urls
}

func parseIPs(t *testing.T, ipStrs []string) []net.IP {
	var ips []net.IP

	for _, i := range ipStrs {
		ips = append(ips, []byte(i))
	}

	return ips
}
