// Package acmedns implements a DNS provider for solving DNS-01 challenges using
// Joohoi's acme-dns project. For more information see the ACME-DNS homepage:
//    https://github.com/joohoi/acme-dns
// This code was adapted from lego:
// 	  https://github.com/xenolf/lego
package acmedns

import (
	"encoding/json"
	"fmt"
	"github.com/cpu/goacmedns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"os"
	"time"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	client   goacmedns.Client
	accounts map[string]goacmedns.Account
}

// NewDNSProvider returns a DNSProvider instance configured for ACME DNS
// Credentials and acme-dns server host are given in environment variables
func NewDNSProvider() (*DNSProvider, error) {
	host := os.Getenv("ACME_DNS_HOST")
	accountJson := os.Getenv("ACME_DNS_ACCOUNTS_JSON")
	return NewDNSProviderHostBytes(host, []byte(accountJson))
}

// NewDNSProviderHostBytes returns a DNSProvider instance configured for ACME DNS
// acme-dns server host is given in a string
// credentials are stored in json in the given string
func NewDNSProviderHostBytes(host string, accountJson []byte) (*DNSProvider, error) {
	client := goacmedns.NewClient(host)

	var accounts map[string]goacmedns.Account
	if err := json.Unmarshal(accountJson, &accounts); err != nil {
		return nil, err
	}

	return &DNSProvider{
		client:   client,
		accounts: accounts,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	// fqdn, ttl are unused by ACME DNS
	_, value, _, err := util.DNS01Record(domain, keyAuth)

	if err != nil {
		return err
	}


	if account, exists := c.accounts[domain]; exists {
		// Update the acme-dns TXT record.
		return c.client.UpdateTXTRecord(account, value)
	}

	return fmt.Errorf("account credentials not found for domain %s", domain)
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
