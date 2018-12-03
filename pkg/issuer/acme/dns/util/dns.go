// +skip_license_check

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
func DNS01Record(domain, value string, nameservers []string, followCNAME bool) (string, string, int, error) {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)

	// Check if the domain has CNAME then return that
	if followCNAME {
		r, err := dnsQuery(fqdn, dns.TypeCNAME, nameservers, true)
		if err == nil && r.Rcode == dns.RcodeSuccess {
			fqdn = updateDomainWithCName(r, fqdn)
		}
		if err != nil {
			return "", "", 0, err
		}
	}

	return fqdn, value, 60, nil
}
