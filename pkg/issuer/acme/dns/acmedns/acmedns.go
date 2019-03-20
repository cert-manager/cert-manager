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

	"github.com/cpu/goacmedns"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	client   goacmedns.Client
	accounts map[string]goacmedns.Account
}

// NewDNSProviderHostBytes returns a DNSProvider instance configured for ACME DNS
// acme-dns server host is given in a string
// credentials are stored in json in the given string
func NewDNSProviderHostBytes(host string, accountJson []byte) (*DNSProvider, error) {
	client := goacmedns.NewClient(host)

	var accounts map[string]goacmedns.Account
	if err := json.Unmarshal(accountJson, &accounts); err != nil {
		return nil, fmt.Errorf("error unmarshalling accountJson: %s", err)
	}

	return &DNSProvider{
		client:   client,
		accounts: accounts,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, value string) error {
	if account, exists := c.accounts[domain]; exists {
		// Update the acme-dns TXT record.
		return c.client.UpdateTXTRecord(account, value)
	}

	return fmt.Errorf("account credentials not found for domain %s", domain)
}
