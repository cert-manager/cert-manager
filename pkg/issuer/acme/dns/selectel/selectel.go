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

// Package selectel implements a DNS provider for solving the DNS-01
// challenge using Selectel Domains API.
package selectel

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	baseURL            = "https://api.selectel.ru/domains/v1"
	userAgent          = "jetstack-cert-manager"
	minTTL             = 60
	propogationTimeout = 120 * time.Second
	pollingInterval    = 2 * time.Second
	httpTimeout        = 30 * time.Second
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface.
type DNSProvider struct {
	dns01Nameservers []string
	client           *Client
}

// NewDNSProvider returns a DNSProvider instance configured for Selectel Domains API.
func NewDNSProvider(token string, dns01Nameservers []string) (*DNSProvider, error) {

	if token == "" {
		return nil, errors.New("selectel: API token is missing")
	}

	client := NewClient(ClientOpts{
		BaseURL:   baseURL,
		Token:     token,
		UserAgent: userAgent,
		HTTPClient: &http.Client{
			Timeout: httpTimeout,
		},
	})

	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		client:           client,
	}, nil
}

// Timeout returns the Timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return propogationTimeout, pollingInterval
}

// Present creates a TXT record to fulfill DNS-01 challenge.
func (d *DNSProvider) Present(domain, fqdn, value string) error {
	domainObj, err := d.client.GetDomainByName(domain)
	if err != nil {
		return fmt.Errorf("selectel: %v", err)
	}

	txtRecord := Record{
		Type:    "TXT",
		TTL:     minTTL,
		Name:    fqdn,
		Content: value,
	}
	_, err = d.client.AddRecord(domainObj.ID, txtRecord)
	if err != nil {
		return fmt.Errorf("selectel: %v", err)
	}

	return nil
}

// CleanUp removes a TXT record used for DNS-01 challenge.
func (d *DNSProvider) CleanUp(domain, fqdn, value string) error {
	domainObj, err := d.client.GetDomainByName(domain)
	if err != nil {
		return fmt.Errorf("selectel: %v", err)
	}

	recordName := unFqdn(fqdn)
	records, err := d.client.ListRecords(domainObj.ID)
	if err != nil {
		return fmt.Errorf("selectel: %v", err)
	}

	// Delete records with specific recordName
	var lastErr error
	for _, record := range records {
		if record.Name == recordName {
			err = d.client.DeleteRecord(domainObj.ID, record.ID)
			if err != nil {
				lastErr = fmt.Errorf("selectel: %v", err)
			}
		}
	}

	return lastErr
}
