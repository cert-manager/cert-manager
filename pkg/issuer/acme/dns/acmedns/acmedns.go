// Package acmedns implements a DNS provider for solving DNS-01 challenges using
// Joohoi's acme-dns project. For more information see the ACME-DNS homepage:
//    https://github.com/joohoi/acme-dns
package acmedns

import (
	"errors"
	"fmt"

	"github.com/cpu/goacmedns"
	"time"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
}

// NewDNSProvider returns a DNSProvider instance configured for ACME DNS
// Credentials are handled automatically by the API
func NewDNSProvider() (*DNSProvider, error) {
	return &DNSProvider{}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	return nil
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
