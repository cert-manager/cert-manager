/*
Copyright 2020 The cert-manager Authors.

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
//
//	https://github.com/joohoi/acme-dns
//
// This code was adapted from lego:
//
//	https://github.com/xenolf/lego
package acmedns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/nrdcg/goacmedns"

	utiloptions "github.com/cert-manager/cert-manager/internal/options"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	client   *goacmedns.Client
	accounts map[string]goacmedns.Account
}

// NewDNSProviderFromOptions returns a DNSProvider configured from the given options.
//
// ctx is not used by this provider; it is accepted to standardize the constructor signature across all providers.
func NewDNSProviderFromOptions(_ context.Context, options ...DNSProviderOption) (*DNSProvider, error) {
	var opt DNSProviderOptions
	for _, o := range options {
		o.ApplyToDNSProviderOptions(&opt)
	}

	err := errors.Join(
		utiloptions.Required(&opt.Host, "host is required"),
		utiloptions.NotEmpty(&opt.AccountJSON, "account json is required"),
	)

	if err != nil {
		return nil, err
	}

	var clientOpts []goacmedns.Option
	if opt.HTTPClient != nil {
		clientOpts = append(clientOpts, goacmedns.WithHTTPClient(opt.HTTPClient))
	}

	client, err := goacmedns.NewClient(opt.Host, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("Error creating acme-dns client: %s", err)
	}

	var accounts map[string]goacmedns.Account
	if err := json.Unmarshal(opt.AccountJSON, &accounts); err != nil {
		return nil, fmt.Errorf("Error unmarshalling accountJSON: %s", err)
	}

	return &DNSProvider{
		client:   client,
		accounts: accounts,
	}, nil
}

// NewDNSProvider returns a DNSProvider instance configured for ACME DNS
// Credentials and acme-dns server host are given in environment variables
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	return NewDNSProviderFromOptions(context.Background(),
		Host(os.Getenv("ACME_DNS_HOST")),
		AccountJSON([]byte(os.Getenv("ACME_DNS_ACCOUNT_JSON"))),
	)
}

// NewDNSProviderHostBytes returns a DNSProvider instance configured for ACME DNS
// acme-dns server host is given in a string
// credentials are stored in json in the given string
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProviderHostBytes(host string, accountJSON []byte, dns01Nameservers []string) (*DNSProvider, error) {
	return NewDNSProviderFromOptions(context.Background(),
		Host(host),
		AccountJSON(accountJSON),
	)
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	if account, exists := c.accounts[domain]; exists {
		// Update the acme-dns TXT record.
		return c.client.UpdateTXTRecord(ctx, account, value)
	}

	return fmt.Errorf("account credentials not found for domain %s", domain)
}

// CleanUp removes the record matching the specified parameters. It is not
// implemented for the ACME-DNS provider.
func (c *DNSProvider) CleanUp(_ context.Context, _, _, _ string) error {
	// ACME-DNS doesn't support the notion of removing a record. For users of
	// ACME-DNS it is expected the stale records remain in-place.
	return nil
}
