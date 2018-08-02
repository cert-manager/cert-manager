// Package acmedns implements a DNS provider for solving DNS-01 challenges using
// Joohoi's acme-dns project. For more information see the ACME-DNS homepage:
//    https://github.com/joohoi/acme-dns
// This code was adapted from lego:
// 	  https://github.com/xenolf/lego
package acmedns

import (
	"github.com/cpu/goacmedns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"os"
	"time"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	client goacmedns.Client
}

// NewDNSProvider returns a DNSProvider instance configured for ACME DNS
// Credentials are handled automatically by the API
// API base URL is assumed to be in an environment variable
func NewDNSProvider() (*DNSProvider, error) {
	apiBase := os.Getenv("ACME_DNS_API_BASE")
	return NewDNSProviderApiBase(apiBase)
}

// NewDNSProvider returns a DNSProvider instance configured for ACME DNS
// Credentials are handled automatically by the API
// API base URL given in parameters
func NewDNSProviderApiBase(apiBase string) (*DNSProvider, error) {
	client := goacmedns.NewClient(apiBase)

	return &DNSProvider{
		client: client,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	// TODO need to fetch credentials from storage and register/store them
	// TODO if they do not exist. User needs to be informed of CNAME records
	// TODO relevant lego code is commented out below for reference

	// ttl is unused by ACME DNS
	fqdn, value, _ := util.DNS01Record(domain, keyAuth)

	// Check if credentials were previously saved for this domain.
	// account, err := c.storage.Fetch(domain)
	//
	// Errors other than goacmeDNS.ErrDomainNotFound are unexpected.
	//if err != nil && err != goacmedns.ErrDomainNotFound {
	//	return err
	//}
	//if err == goacmedns.ErrDomainNotFound {
	//	// The account did not exist. Create a new one and return an error
	//	// indicating the required one-time manual CNAME setup.
	//	return c.register(domain, fqdn)
	//}

	// Update the acme-dns TXT record.
	return c.client.UpdateTXTRecord(account, value)
}

// CleanUp removes the record matching the specified parameters. It is not
// implemented for the ACME-DNS provider.
func (c *DNSProvider) CleanUp(_, _, _ string) error {
	// ACME-DNS doesn't support the notion of removing a record. For users of
	// ACME-DNS it is expected the stale records remain in-place.
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}
