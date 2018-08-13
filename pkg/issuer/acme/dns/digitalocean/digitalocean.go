/*
Copyright 2018 The Jetstack cert-manager contributors.
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
	"time"

	"github.com/digitalocean/godo"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/miekg/dns"

	"golang.org/x/oauth2"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *godo.Client
}

// NewDNSProvider returns a DNSProvider instance configured for digitalocean.
// The access token must be passed in the environment variable DIGITALOCEAN_TOKEN
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	token := os.Getenv("DIGITALOCEAN_TOKEN")
	return NewDNSProviderCredentials(token, dns01Nameservers)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for digitalocean.
func NewDNSProviderCredentials(token string, dns01Nameservers []string) (*DNSProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("DigitalOcean token missing")
	}

	c := oauth2.NewClient(
		context.Background(),
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
	)

	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		client:           godo.NewClient(c),
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl, err := util.DNS01Record(domain, keyAuth, c.dns01Nameservers)
	if err != nil {
		return err
	}

	// if DigitalOcean does not have this zone then we will find out later
	zoneName, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return err
	}

	alreadyExists := false

	// check if the record has already been created
	domains, _, err := c.client.Domains.List(context.Background(), &godo.ListOptions{})
	for _, domain := range domains {
		// we're only interested in the challenge domain, so skip the rest
		if dns.Fqdn(domain.Name) == fqdn {
			// loop over each record in the domain
			// the digitalocean API only returns a zone file, so we need to parse it first
			for x := range dns.ParseZone(strings.NewReader(domain.ZoneFile), "", "") {
				if x.Error != nil {
					return x.Error
				} else {
					// check if this record is a TXT
					if x.RR.Header().Rrtype == dns.TypeTXT {
						txt := x.RR.(*dns.TXT).Txt
						for _, c := range txt {
							// skip creation if it has the correct value
							if c == keyAuth {
								alreadyExists = true
							}
						}
					}
				}
			}
		}
	}

	if alreadyExists {
		return nil
	}

	createRequest := &godo.DomainRecordEditRequest{
		Type: "TXT",
		Name: fqdn,
		Data: value,
		TTL:  ttl,
	}

	_, _, err = c.client.Domains.CreateRecord(
		context.Background(),
		util.UnFqdn(zoneName),
		createRequest,
	)

	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _, err := util.DNS01Record(domain, keyAuth, c.dns01Nameservers)
	if err != nil {
		return err
	}

	zoneName, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)

	records, err := c.findTxtRecord(fqdn)
	if err != nil {
		return err
	}

	for _, record := range records {
		_, err = c.client.Domains.DeleteRecord(context.Background(), util.UnFqdn(zoneName), record.ID)

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *DNSProvider) findTxtRecord(fqdn string) ([]godo.DomainRecord, error) {

	zoneName, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return nil, err
	}

	allRecords, _, err := c.client.Domains.Records(
		context.Background(),
		util.UnFqdn(zoneName),
		nil,
	)

	var records []godo.DomainRecord

	for _, record := range allRecords {
		if util.ToFqdn(record.Name) == fqdn {
			records = append(records, record)
		}
	}

	return records, err
}
