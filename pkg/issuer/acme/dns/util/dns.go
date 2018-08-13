/*
Copyright 2018 The Jetstack cert-manager contributors.

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

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package util

import (
	"fmt"

	"github.com/miekg/dns"
)

// DNS01Record returns a DNS record which will fulfill the `dns-01` challenge
// TODO: move this into a non-generic place by resolving import cycle in dns package
func DNS01Record(domain, value string) (string, string, int, error) {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)

	// Check if the domain has CNAME then return that
	r, err := dnsQuery(fqdn, dns.TypeCNAME, RecursiveNameservers, true)
	if err == nil && r.Rcode == dns.RcodeSuccess {
		fqdn = updateDomainWithCName(r, fqdn)
	}
	if err != nil {
		return "", "", 0, err
	}
	return fqdn, value, 60, nil
}
