// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package azuredns implements a DNS provider for solving the DNS-01 challenge
// using Azure DNS.
package azuredns

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/arm/dns"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers  []string
	recordClient      dns.RecordSetsClient
	zoneClient        dns.ZonesClient
	resourceGroupName string
	zoneName          string
}

// NewDNSProvider returns a DNSProvider instance configured for the Azure
// DNS service.
// Credentials are automatically detected from environment variables
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {

	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	tenantID := os.Getenv("AZURE_TENANT_ID")
	resourceGroupName := ("AZURE_RESOURCE_GROUP")
	zoneName := ("AZURE_ZONE_NAME")

	return NewDNSProviderCredentials(clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName, dns01Nameservers)
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Azure
// DNS service using static credentials from its parameters
func NewDNSProviderCredentials(clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName string, dns01Nameservers []string) (*DNSProvider, error) {
	oauthConfig, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, err
	}

	spt, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, azure.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	rc := dns.NewRecordSetsClient(subscriptionID)
	rc.Authorizer = autorest.NewBearerAuthorizer(spt)

	zc := dns.NewZonesClient(subscriptionID)
	zc.Authorizer = autorest.NewBearerAuthorizer(spt)

	return &DNSProvider{
		dns01Nameservers:  dns01Nameservers,
		recordClient:      rc,
		zoneClient:        zc,
		resourceGroupName: resourceGroupName,
		zoneName:          zoneName,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl, err := util.DNS01Record(domain, keyAuth, c.dns01Nameservers)
	if err != nil {
		return err
	}

	return c.createRecord(fqdn, value, ttl)
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _, err := util.DNS01Record(domain, keyAuth, c.dns01Nameservers)
	if err != nil {
		return err
	}

	z, err := c.getHostedZoneName(fqdn)
	if err != nil {
		log.Fatalf("Error getting hosted zone name for: %s, %v", fqdn, err)
		return err
	}

	_, err = c.recordClient.Delete(
		c.resourceGroupName,
		z,
		c.trimFqdn(fqdn),
		dns.TXT, "")

	if err != nil {
		return err
	}
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

func (c *DNSProvider) createRecord(fqdn, value string, ttl int) error {
	rparams := &dns.RecordSet{
		RecordSetProperties: &dns.RecordSetProperties{
			TTL: to.Int64Ptr(int64(ttl)),
			TxtRecords: &[]dns.TxtRecord{
				{Value: &[]string{value}},
			},
		},
	}

	z, err := c.getHostedZoneName(fqdn)
	if err != nil {
		log.Fatalf("Error getting hosted zone name for: %s, %v", fqdn, err)
		return err
	}

	_, err = c.recordClient.CreateOrUpdate(
		c.resourceGroupName,
		z,
		c.trimFqdn(fqdn),
		dns.TXT,
		*rparams, "", "")

	if err != nil {
		log.Fatalf("Error creating TXT: %s, %v", c.zoneName, err)
		return err
	}
	return nil
}

func (c *DNSProvider) getHostedZoneName(fqdn string) (string, error) {
	if c.zoneName != "" {
		return c.zoneName, nil
	}
	z, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return "", err
	}

	if len(z) == 0 {
		return "", fmt.Errorf("Zone %s not found for domain %s", z, fqdn)
	}

	_, err = c.zoneClient.Get(c.resourceGroupName, util.UnFqdn(z))

	if err != nil {
		return "", fmt.Errorf("Zone %s not found in AzureDNS for domain %s. Err: %v", z, fqdn, err)
	}

	return util.UnFqdn(z), nil
}

func (c *DNSProvider) trimFqdn(fqdn string) string {
	return strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), "."+c.zoneName)
}
