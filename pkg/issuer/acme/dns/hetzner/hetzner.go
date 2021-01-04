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

// Package hetzner implements a DNS provider for solving the DNS-01
// challenge using hetzner DNS.
package hetzner

import (
	"fmt"
	"os"
	"strings"

	hclouddns "git.blindage.org/21h/hcloud-dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           hclouddns.HCloudClientAdapter
}

// NewDNSProvider returns a DNSProvider instance configured for digitalocean.
// The access token must be passed in the environment variable DIGITALOCEAN_TOKEN
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	token := os.Getenv("HETZNER_TOKEN")
	return NewDNSProviderCredentials(token, dns01Nameservers)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for digitalocean.
func NewDNSProviderCredentials(token string, dns01Nameservers []string) (*DNSProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("Hetzner token missing")
	}

	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		client:           hclouddns.New(token),
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	// if Hetzner does not have this zone then we will find out later
	zoneName, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)
	if err != nil {
		return err
	}

	// check if the record has already been created
	records, err := c.findTxtRecord(fqdn)
	if err != nil {
		return err
	}

	for _, record := range records {
		if record.RecordType == "TXT" && record.Value == value {
			return nil
		}
	}

	createRequest := hclouddns.HCloudRecord{
		ZoneID:     zoneName,
		RecordType: "TXT",
		Name:       fqdn,
		Value:      value,
		TTL:        60,
	}

	_, err = c.client.CreateRecord(createRequest)

	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	records, err := c.findTxtRecord(fqdn)
	if err != nil {
		return err
	}

	for _, record := range records {
		_, err = c.client.DeleteRecord(record.ID)

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *DNSProvider) findTxtRecord(fqdn string) ([]hclouddns.HCloudRecord, error) {
	zoneName, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)
	if err != nil {
		return nil, err
	}

	allRecords, err := c.client.GetRecords(hclouddns.HCloudGetRecordsParams{ZoneID: util.UnFqdn(zoneName)})

	var records []hclouddns.HCloudRecord

	// The record Name doesn't contain the zoneName, so
	// lets remove it before filtering the array of record
	targetName := fqdn
	if strings.HasSuffix(fqdn, zoneName) {
		targetName = fqdn[:len(fqdn)-len(zoneName)]
	}

	for _, record := range allRecords.Records {
		if util.ToFqdn(record.Name) == targetName {
			records = append(records, record)
		}
	}

	return records, err
}
