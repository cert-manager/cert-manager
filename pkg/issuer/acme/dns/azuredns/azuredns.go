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
	"context"

	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2017-10-01/dns"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	recordClient      dns.RecordSetsClient
	zoneClient        dns.ZonesClient
	resourceGroupName string
	zoneName          string
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Azure
// DNS service using static credentials from its parameters
func NewDNSProviderCredentials(clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName string) (*DNSProvider, error) {
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
		recordClient:      rc,
		zoneClient:        zc,
		resourceGroupName: resourceGroupName,
		zoneName:          zoneName,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, fqdn, zone, value string) error {
	return c.createRecord(fqdn, value, zone, 60)
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, zone, value string) error {
	_, err := c.recordClient.Delete(
		context.TODO(),
		c.resourceGroupName,
		zone,
		util.UnFqdn(fqdn),
		dns.TXT, "")

	if err != nil {
		return err
	}
	return nil
}

func (c *DNSProvider) createRecord(fqdn, value, zone string, ttl int) error {
	rparams := &dns.RecordSet{
		RecordSetProperties: &dns.RecordSetProperties{
			TTL: to.Int64Ptr(int64(ttl)),
			TxtRecords: &[]dns.TxtRecord{
				{Value: &[]string{value}},
			},
		},
	}

	_, err := c.recordClient.CreateOrUpdate(
		context.TODO(),
		c.resourceGroupName,
		zone,
		util.UnFqdn(fqdn),
		dns.TXT,
		*rparams, "", "")

	if err != nil {
		klog.Infof("Error creating TXT: %s, %v", zone, err)
		return err
	}
	return nil
}
