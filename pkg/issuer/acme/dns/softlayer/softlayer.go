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

// Package softlayer implements a DNS provider for solving DNS-01 challenges using
// the official softlayer-go project.
//    https://github.com/softlayer/softlayer-go
package softlayer

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/softlayer/softlayer-go/datatypes"
	"github.com/softlayer/softlayer-go/filter"
	"github.com/softlayer/softlayer-go/services"
	"github.com/softlayer/softlayer-go/session"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	authUsername     string
	authKey          string
	session          *session.Session
}

// NewDNSProvider returns a NewDNSProviderCredentials instance configured for Softlayer DNS
// Credentials are given in environment variables
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	username := os.Getenv("SL_USERNAME")
	apikey := os.Getenv("SL_API_KEY")
	return NewDNSProviderCredentials(username, apikey, dns01Nameservers)
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for Softlayer DNS
// credentials are stored in json in the given string
func NewDNSProviderCredentials(username, apikey string, dns01Nameservers []string) (*DNSProvider, error) {
	if username == "" || apikey == "" {
		return nil, fmt.Errorf("Softlayer credentials missing")
	}

	sess := session.New(username, apikey)

	return &DNSProvider{
		authUsername:     username,
		authKey:          apikey,
		dns01Nameservers: dns01Nameservers,
		session:          sess,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	zoneName, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)
	if err != nil {
		return err
	}

	zone, err := c.getHostedZone(zoneName)
	if err != nil {
		return err
	}

	// Look for existing records.
	svc := services.GetDnsDomainService(c.session)
	records, err := svc.Id(*zone).GetResourceRecords()
	if len(records) == 0 || err != nil {
		return err
	}

	entry := strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), "."+domain)

	recordsTxt, err := c.findTxtRecords(*zone, entry)
	if err != nil {
		return err
	}
	for _, r := range recordsTxt {
		if r.Data == &value {
			// the record is already set to the desired value
			return nil
		}
	}

	if len(recordsTxt) >= 1 {
		svcRecord := services.GetDnsDomainResourceRecordService(c.session)
		del, err := svcRecord.DeleteObjects(recordsTxt)
		if del == false || err != nil {
			return err
		}
	}

	ttl := 60
	_, err = svc.Id(*zone).CreateTxtRecord(&entry, &value, &ttl)
	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (c *DNSProvider) CleanUp(domain, fqdn, key string) error {
	zoneName, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)
	if err != nil {
		return err
	}

	zone, err := c.getHostedZone(zoneName)
	if err != nil {
		return err
	}

	entry := strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), "."+domain)
	records, err := c.findTxtRecords(*zone, entry)
	if err != nil {
		return err
	}

	svc := services.GetDnsDomainResourceRecordService(c.session)
	del, err := svc.DeleteObjects(records)
	if del == false || err != nil {
		return err
	}

	return nil
}

// Timeout customizes the timeout values used by the ACME package for checking
// DNS record validity.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 180 * time.Second, 5 * time.Second
}

// getHostedZone returns the managed-zone
func (c *DNSProvider) getHostedZone(domain string) (*int, error) {
	svc := services.GetDnsDomainService(c.session)

	domainFqdn := util.UnFqdn(domain)
	zones, err := svc.GetByDomainName(&domainFqdn)

	if err != nil {
		return nil, fmt.Errorf("Softlayer API call failed: %v", err)
	}

	if len(zones) == 0 {
		return nil, fmt.Errorf("No matching Softlayer domain found for domain %s", domain)
	}

	if len(zones) > 1 {
		return nil, fmt.Errorf("Too many Softlayer domains found for domain %s", domain)
	}

	return zones[0].Id, nil
}

func (c *DNSProvider) findTxtRecords(zone int, entry string) ([]datatypes.Dns_Domain_ResourceRecord, error) {
	txtType := "txt"
	// Look for existing records.
	svc := services.GetDnsDomainService(c.session)

	filters := filter.New(
		filter.Path("resourceRecords.type").Eq(txtType),
		filter.Path("resourceRecords.host").Eq(entry),
	)

	recs, err := svc.Id(zone).Filter(filters.Build()).GetResourceRecords()
	if err != nil {
		return nil, err
	}

	found := []datatypes.Dns_Domain_ResourceRecord{}
	for _, r := range recs {
		if *r.Type == txtType && *r.Host == entry {
			found = append(found, r)
		}
	}

	return found, nil
}
