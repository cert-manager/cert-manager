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
	"github.com/miekg/dns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func DNSZones(sel cmacme.CertificateDNSNameSelector) Selector {
	return &dnsZonesSelector{
		allowedDNSZones: sel.DNSZones,
	}
}

type dnsZonesSelector struct {
	allowedDNSZones []string
}

func (s *dnsZonesSelector) Matches(meta metav1.ObjectMeta, dnsName string) (bool, int) {
	if len(s.allowedDNSZones) == 0 {
		return true, 0
	}

	maxMatchingLabels := 0
	for _, zone := range s.allowedDNSZones {
		numMatchingLabels := dns.CompareDomainName(zone, dnsName)
		if numMatchingLabels != dns.CountLabel(zone) {
			continue
		}

		if numMatchingLabels > maxMatchingLabels {
			maxMatchingLabels = numMatchingLabels
		}
	}

	return maxMatchingLabels > 0, maxMatchingLabels
}
