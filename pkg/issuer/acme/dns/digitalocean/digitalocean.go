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

// Package digitalocean implements a DNS provider for solving the DNS-01
// challenge using digitalocean DNS.
package digitalocean

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/digitalocean/godo"
	"golang.org/x/oauth2"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *godo.Client
}

// NewDNSProvider returns a DNSProvider instance configured for digitalocean.
// The access token must be passed in the environment variable DIGITALOCEAN_TOKEN
func NewDNSProvider(dns01Nameservers []string, userAgent string) (*DNSProvider, error) {
	token := os.Getenv("DIGITALOCEAN_TOKEN")
	return NewDNSProviderCredentials(token, dns01Nameservers, userAgent)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for digitalocean.
func NewDNSProviderCredentials(token string, dns01Nameservers []string, userAgent string) (*DNSProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("DigitalOcean token missing")
	}

	unusedCtx := context.Background() // context is not actually used
	c := oauth2.NewClient(unusedCtx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))

	clientOpts := []godo.ClientOpt{godo.SetUserAgent(userAgent)}
	client, err := godo.New(c, clientOpts...)
	if err != nil {
		return nil, err
	}

	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		client:           client,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	// if DigitalOcean does not have this zone then we will find out later
	zoneName, err := util.FindZoneByFqdn(ctx, fqdn, c.dns01Nameservers)
	if err != nil {
		return err
	}

	// check if the record has already been created
	records, err := c.findTxtRecord(ctx, fqdn)
	if err != nil {
		return err
	}

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
		ctx,
		util.UnFqdn(zoneName),
		createRequest,
	)

	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	zoneName, err := util.FindZoneByFqdn(ctx, fqdn, c.dns01Nameservers)
	if err != nil {
		return err
	}

	records, err := c.findTxtRecord(ctx, fqdn)
	if err != nil {
		return err
	}

	for _, record := range records {
		_, err = c.client.Domains.DeleteRecord(ctx, util.UnFqdn(zoneName), record.ID)

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *DNSProvider) findTxtRecord(ctx context.Context, fqdn string) ([]godo.DomainRecord, error) {
	zoneName, err := util.FindZoneByFqdn(ctx, fqdn, c.dns01Nameservers)
	if err != nil {
		return nil, err
	}

	allRecords, _, err := c.client.Domains.RecordsByType(
		ctx,
		util.UnFqdn(zoneName),
		"TXT",
		nil,
	)

	var records []godo.DomainRecord

	// The record Name doesn't contain the zoneName, so
	// lets remove it before filtering the array of record
	targetName := fqdn
	if strings.HasSuffix(fqdn, zoneName) {
		targetName = fqdn[:len(fqdn)-len(zoneName)]
	}

	for _, record := range allRecords {
		if util.ToFqdn(record.Name) == targetName {
			records = append(records, record)
		}
	}

	return records, err
}
