// Package digitalocean implements a DNS provider for solving the DNS-01
// challenge using digitalocean DNS.
package digitalocean

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/digitalocean/godo"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"

	"golang.org/x/oauth2"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	client *godo.Client
}

// NewDNSProvider returns a DNSProvider instance configured for digitalocean.
// The access token must be passed in the environment variable DIGITALOCEAN_TOKEN
func NewDNSProvider() (*DNSProvider, error) {
	token := os.Getenv("DIGITALOCEAN_TOKEN")
	return NewDNSProviderCredentials(token)
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

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := util.DNS01Record(domain, keyAuth)

	// if DigitalOcean does not have this zone then we will find out later
	zoneName, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return err
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
	fqdn, _, _ := util.DNS01Record(domain, keyAuth)

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
