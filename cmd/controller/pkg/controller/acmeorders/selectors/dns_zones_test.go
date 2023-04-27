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

package selectors

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func TestDNSZones(t *testing.T) {
	tests := []struct {
		name     string
		selector cmacme.CertificateDNSNameSelector
		meta     metav1.ObjectMeta
		dnsName  string
		matches  bool
		score    int
	}{
		{
			name:     "matching a domain with an empty selector",
			selector: cmacme.CertificateDNSNameSelector{},
			dnsName:  "www.example.com",
			matches:  true,
			score:    0,
		},
		{
			name: "matching a domain in a zone",
			selector: cmacme.CertificateDNSNameSelector{
				DNSZones: []string{"example.com"},
			},
			dnsName: "www.example.com",
			matches: true,
			score:   2,
		},
		{
			name: "matching a wildcard domain in a zone",
			selector: cmacme.CertificateDNSNameSelector{
				DNSZones: []string{"example.com"},
			},
			dnsName: "*.example.com",
			matches: true,
			score:   2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSelector(t, DNSZones(test.selector), test.meta, test.dnsName, test.matches, test.score)
		})
	}
}

func testSelector(t *testing.T, sel Selector, meta metav1.ObjectMeta, dnsName string, expectMatch bool, expectedScore int) {
	matches, score := sel.Matches(meta, dnsName)
	if matches != expectMatch {
		t.Errorf("expected match to be %t but it was %t", expectMatch, matches)
	}
	if score != expectedScore {
		t.Errorf("expected score to be %d but it was %d", expectedScore, score)
	}
}
