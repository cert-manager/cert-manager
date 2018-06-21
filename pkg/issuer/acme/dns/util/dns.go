package util

import (
	"fmt"

	"github.com/miekg/dns"
)

// DNS01Record returns a DNS record which will fulfill the `dns-01` challenge
// TODO: move this into a non-generic place by resolving import cycle in dns package
func DNS01Record(domain, value string) (string, string, int) {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)

	// Check if the domain has CNAME then return that
	r, err := dnsQuery(fqdn, dns.TypeCNAME, RecursiveNameservers, true)
	if err == nil && r.Rcode == dns.RcodeSuccess {
		fqdn = updateDomainWithCName(r, fqdn)
	}
	return fqdn, value, 60
}
