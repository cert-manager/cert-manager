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

// Package digitalocean implements a DNS provider for solving the DNS-01
// challenge using digitalocean DNS.
package digitalocean

import (
	"context"
	"fmt"
	"strings"

	"github.com/digitalocean/godo"
	"golang.org/x/oauth2"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	client *godo.Client
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for digitalocean.
func NewDNSProviderCredentials(token string) (*DNSProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("DigitalOcean token missing")
	}

	c := oauth2.NewClient(
		context.Background(),
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
	)

	return &DNSProvider{
		client: godo.NewClient(c),
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, fqdn, zone, value string) error {
	// check if the record has already been created
	records, err := c.findTxtRecord(fqdn, zone)
	for _, record := range records {
		if record.Type == "TXT" && record.Data == value {
			return nil
		}

	}

	createRequest := &godo.DomainRecordEditRequest{
		Type: "TXT",
		Name: fqdn,
		Data: value,
		TTL:  60,
	}

	_, _, err = c.client.Domains.CreateRecord(
		context.Background(),
		util.UnFqdn(zone),
		createRequest,
	)

	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, zone, value string) error {
	records, err := c.findTxtRecord(fqdn, zone)
	if err != nil {
		return err
	}

	for _, record := range records {
		_, err = c.client.Domains.DeleteRecord(context.Background(), util.UnFqdn(zone), record.ID)

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *DNSProvider) findTxtRecord(fqdn, zone string) ([]godo.DomainRecord, error) {
	allRecords, _, err := c.client.Domains.Records(
		context.Background(),
		util.UnFqdn(zone),
		nil,
	)

	var records []godo.DomainRecord

	// The record Name doesn't contain the zoneName, so
	// lets remove it before filtering the array of record
	targetName := fqdn
	if strings.HasSuffix(fqdn, zone) {
		targetName = fqdn[:len(fqdn)-len(zone)]
	}

	for _, record := range allRecords {
		if util.ToFqdn(record.Name) == targetName {
			records = append(records, record)
		}
	}

	return records, err
}
