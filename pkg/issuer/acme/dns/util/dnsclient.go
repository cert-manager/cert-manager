package util

import (
	"fmt"

	"github.com/miekg/dns"
)

type DNSClient struct {
	Nameservers []string
}

// DNS01Record returns a DNS record which will fulfill the `dns-01` challenge
func (d *DNSClient) DNS01Record(domain, value string) (string, string, int, error) {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)

	fmt.Println("using dns servers: ", d.Nameservers)

	// Check if the domain has CNAME then return that
	r, err := dnsQuery(fqdn, dns.TypeCNAME, d.Nameservers, true)
	if err == nil && r.Rcode == dns.RcodeSuccess {
		fqdn = updateDomainWithCName(r, fqdn)
	}
	if err != nil {
		return "", "", 0, err
	}
	return fqdn, value, 60, nil
}

func (d *DNSClient) FindZoneByFqdn(fqdn string) (string, error) {
	return FindZoneByFqdn(fqdn, d.Nameservers)
}
