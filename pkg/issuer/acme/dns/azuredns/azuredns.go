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
	"fmt"
	"strings"

	"github.com/go-logr/logr"

	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2017-10-01/dns"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers  []string
	recordClient      dns.RecordSetsClient
	zoneClient        dns.ZonesClient
	resourceGroupName string
	zoneName          string
	log               logr.Logger
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Azure
// DNS service using static credentials from its parameters
func NewDNSProviderCredentials(environment, clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName string, dns01Nameservers []string, ambient bool) (*DNSProvider, error) {
	env := azure.PublicCloud
	if environment != "" {
		var err error
		env, err = azure.EnvironmentFromName(environment)
		if err != nil {
			return nil, err
		}
	}

	spt, err := getAuthorization(env, clientID, clientSecret, subscriptionID, tenantID, ambient)
	if err != nil {
		return nil, err
	}

	rc := dns.NewRecordSetsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID)
	rc.Authorizer = autorest.NewBearerAuthorizer(spt)

	zc := dns.NewZonesClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID)
	zc.Authorizer = autorest.NewBearerAuthorizer(spt)

	return &DNSProvider{
		dns01Nameservers:  dns01Nameservers,
		recordClient:      rc,
		zoneClient:        zc,
		resourceGroupName: resourceGroupName,
		zoneName:          zoneName,
		log:               logf.Log.WithName("azure-dns"),
	}, nil
}

func getAuthorization(env azure.Environment, clientID, clientSecret, subscriptionID, tenantID string, ambient bool) (*adal.ServicePrincipalToken, error) {
	if clientID != "" {
		logf.Log.V(logf.InfoLevel).Info("azuredns authenticating with clientID and secret key")
		oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, tenantID)
		if err != nil {
			return nil, err
		}
		spt, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, env.ResourceManagerEndpoint)
		if err != nil {
			return nil, err
		}
		return spt, nil
	}
	logf.Log.V(logf.InfoLevel).Info("No ClientID found:  authenticating azuredns with managed identity (MSI)")
	if !ambient {
		return nil, fmt.Errorf("ClientID is not set but neither `--cluster-issuer-ambient-credentials` nor `--issuer-ambient-credentials` are set. These are necessary to enable Azure Managed Identities")
	}
	msiEndpoint, err := adal.GetMSIVMEndpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to get the managed service identity endpoint: %v", err)
	}

	spt, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, env.ServiceManagementEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create the managed service identity token: %v", err)
	}
	return spt, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	return c.createRecord(fqdn, value, 60)
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	z, err := c.getHostedZoneName(fqdn)
	if err != nil {
		c.log.Error(err, "Error getting hosted zone name for:", fqdn)
		return err
	}

	_, err = c.recordClient.Delete(
		context.TODO(),
		c.resourceGroupName,
		z,
		c.trimFqdn(fqdn, z),
		dns.TXT, "")

	if err != nil {
		return err
	}
	return nil
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
		c.log.Error(err, "Error getting hosted zone name for:", fqdn)
		return err
	}

	_, err = c.recordClient.CreateOrUpdate(
		context.TODO(),
		c.resourceGroupName,
		z,
		c.trimFqdn(fqdn, z),
		dns.TXT,
		*rparams, "", "")

	if err != nil {
		c.log.Error(err, "Error creating TXT:", z)
		return err
	}
	return nil
}

func (c *DNSProvider) getHostedZoneName(fqdn string) (string, error) {
	if c.zoneName != "" {
		return c.zoneName, nil
	}
	z, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)
	if err != nil {
		return "", err
	}

	if len(z) == 0 {
		return "", fmt.Errorf("Zone %s not found for domain %s", z, fqdn)
	}

	_, err = c.zoneClient.Get(context.TODO(), c.resourceGroupName, util.UnFqdn(z))

	if err != nil {
		return "", fmt.Errorf("Zone %s not found in AzureDNS for domain %s. Err: %v", z, fqdn, err)
	}

	return util.UnFqdn(z), nil
}

// Trims DNS zone from the fqdn. Defaults to DNSProvider.zoneName if it is specified.
func (c *DNSProvider) trimFqdn(fqdn string, zone string) string {
	z := zone
	if len(c.zoneName) > 0 {
		z = c.zoneName
	}
	return strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), "."+z)
}
