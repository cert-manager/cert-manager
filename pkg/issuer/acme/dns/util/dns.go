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

// DNS01LookupFQDN returns a DNS name which will be updated to solve the dns-01
// challenge
// TODO: move this into the pkg/acme package
func DNS01LookupFQDN(domain string, followCNAME bool, nameservers ...string) (string, error) {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)

	// Check if the domain has CNAME then return that
	if followCNAME {
		r, err := DNSQuery(fqdn, dns.TypeCNAME, nameservers, true)
		if err == nil && r.Rcode == dns.RcodeSuccess {
			fqdn = updateDomainWithCName(r, fqdn)
		}
		if err != nil {
			return "", err
		}
	}

	return fqdn, nil
}
