// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package clouddns implements a DNS provider for solving the DNS-01
// challenge using Google Cloud DNS.
package clouddns

import (
	"fmt"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
)

// DNSProvider is an implementation of the DNSProvider interface.
type DNSProvider struct {
	project string
	client  *dns.Service
}

// NewDNSProviderAmbientCredentials uses ambient credentials to return a
// DNSProvider instance configured for Google Cloud DNS.
func NewDNSProviderAmbientCredentials(project string) (*DNSProvider, error) {
	if project == "" {
		return nil, fmt.Errorf("Google Cloud project name missing")
	}

	client, err := google.DefaultClient(context.Background(), dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return nil, fmt.Errorf("Unable to get Google Cloud client: %v", err)
	}
	svc, err := dns.New(client)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Google Cloud DNS service: %v", err)
	}
	return &DNSProvider{
		project: project,
		client:  svc,
	}, nil
}

// NewDNSProviderServiceAccountBytes uses the supplied service account JSON
// file data to return a DNSProvider instance configured for Google Cloud DNS.
func NewDNSProviderServiceAccountBytes(project string, saBytes []byte) (*DNSProvider, error) {
	if project == "" {
		return nil, fmt.Errorf("Google Cloud project name missing")
	}
	if len(saBytes) == 0 {
		return nil, fmt.Errorf("Google Cloud Service Account data missing")
	}

	conf, err := google.JWTConfigFromJSON(saBytes, dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return nil, fmt.Errorf("Unable to acquire config: %v", err)
	}
	client := conf.Client(oauth2.NoContext)

	svc, err := dns.New(client)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Google Cloud DNS service: %v", err)
	}
	return &DNSProvider{
		project: project,
		client:  svc,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (c *DNSProvider) Present(domain, fqdn, zone, value string) error {
	zone, err := c.lookupHostedZone(zone)
	if err != nil {
		return err
	}

	rec := &dns.ResourceRecordSet{
		Name:    fqdn,
		Rrdatas: []string{value},
		Ttl:     int64(60),
		Type:    "TXT",
	}
	change := &dns.Change{
		Additions: []*dns.ResourceRecordSet{rec},
	}

	// Look for existing records.
	list, err := c.client.ResourceRecordSets.List(c.project, zone).Name(fqdn).Type("TXT").Do()
	if err != nil {
		return err
	}
	if len(list.Rrsets) > 0 {
		// Attempt to delete the existing records when adding our new one.
		change.Deletions = list.Rrsets
	}

	chg, err := c.client.Changes.Create(c.project, zone, change).Do()
	if err != nil {
		return err
	}

	// wait for change to be acknowledged
	for chg.Status == "pending" {
		time.Sleep(time.Second)

		chg, err = c.client.Changes.Get(c.project, zone, chg.Id).Do()
		if err != nil {
			return err
		}
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (c *DNSProvider) CleanUp(domain, fqdn, zone, value string) error {
	zone, err := c.lookupHostedZone(fqdn)
	if err != nil {
		return err
	}

	records, err := c.findTxtRecords(zone, fqdn)
	if err != nil {
		return err
	}

	for _, rec := range records {
		change := &dns.Change{
			Deletions: []*dns.ResourceRecordSet{rec},
		}
		_, err = c.client.Changes.Create(c.project, zone, change).Do()
		if err != nil {
			return err
		}
	}
	return nil
}

// lookupHostedZone returns the managed-zone name after querying the google API
func (c *DNSProvider) lookupHostedZone(zone string) (string, error) {
	zones, err := c.client.ManagedZones.
		List(c.project).
		DnsName(zone).
		Do()
	if err != nil {
		return "", fmt.Errorf("GoogleCloud API call failed: %v", err)
	}

	if len(zones.ManagedZones) == 0 {
		return "", fmt.Errorf("No matching GoogleCloud domain found for zone %s", zone)
	}

	return zones.ManagedZones[0].Name, nil
}

func (c *DNSProvider) findTxtRecords(zone, fqdn string) ([]*dns.ResourceRecordSet, error) {
	recs, err := c.client.ResourceRecordSets.List(c.project, zone).Do()
	if err != nil {
		return nil, err
	}

	found := []*dns.ResourceRecordSet{}
	for _, r := range recs.Rrsets {
		if r.Type == "TXT" && r.Name == fqdn {
			found = append(found, r)
		}
	}

	return found, nil
}
