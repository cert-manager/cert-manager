/*
Copyright 2019 The Jetstack cert-manager contributors.

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

// Package acmedns implements a DNS provider for solving DNS-01 challenges using
// Joohoi's acme-dns project. For more information see the ACME-DNS homepage:
//    https://github.com/joohoi/acme-dns
// This code was adapted from lego:
// 	  https://github.com/xenolf/lego
package acmedns

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cpu/goacmedns"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           goacmedns.Client
	accounts         map[string]goacmedns.Account
}

// NewDNSProvider returns a DNSProvider instance configured for ACME DNS
// Credentials and acme-dns server host are given in environment variables
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	host := os.Getenv("ACME_DNS_HOST")
	accountJson := os.Getenv("ACME_DNS_ACCOUNT_JSON")
	return NewDNSProviderHostBytes(host, []byte(accountJson), dns01Nameservers)
}

// NewDNSProviderHostBytes returns a DNSProvider instance configured for ACME DNS
// acme-dns server host is given in a string
// credentials are stored in json in the given string
func NewDNSProviderHostBytes(host string, accountJson []byte, dns01Nameservers []string) (*DNSProvider, error) {
	client := goacmedns.NewClient(host)

	var accounts map[string]goacmedns.Account
	if err := json.Unmarshal(accountJson, &accounts); err != nil {
		return nil, fmt.Errorf("Error unmarshalling accountJson: %s", err)
	}

	return &DNSProvider{
		client:           client,
		accounts:         accounts,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, fqdn, value string) error {
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
