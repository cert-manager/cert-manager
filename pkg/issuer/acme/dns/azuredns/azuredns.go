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

	"k8s.io/klog"

	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2017-10-01/dns"
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

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Azure
// DNS service using static credentials from its parameters
func NewDNSProviderCredentials(environment, clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName string, ambient bool, dns01Nameservers []string) (*DNSProvider, error) {
	env := azure.PublicCloud
	if environment != "" {
		var err error
		env, err = azure.EnvironmentFromName(environment)
		if err != nil {
			return nil, err
		}
	}

	var token *adal.ServicePrincipalToken
	if clientID != "" {
		oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, tenantID)
		if err != nil {
			return nil, err
		}

		klog.Info("azuredns authenticating with clientID and secret key")
		token, err = adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, env.ResourceManagerEndpoint)
		if err != nil {
			return nil, err
		}
	}

	if token == nil {
		if !ambient {
			return nil, fmt.Errorf("attempting to authenticate using AzureAD Managed Identity but ambient credentials are not enabled")
		}

		klog.Info("azuredns authenticating with managed identity")
		endpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, err
		}

		token, err = adal.NewServicePrincipalTokenFromMSI(endpoint, env.ServiceManagementEndpoint)
		if err != nil {
			return nil, err
		}
	}

	rc := dns.NewRecordSetsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID)
	rc.Authorizer = autorest.NewBearerAuthorizer(token)

	zc := dns.NewZonesClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID)
	zc.Authorizer = autorest.NewBearerAuthorizer(token)

	return &DNSProvider{
		dns01Nameservers:  dns01Nameservers,
		recordClient:      rc,
		zoneClient:        zc,
		resourceGroupName: resourceGroupName,
		zoneName:          zoneName,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	return c.createRecord(fqdn, value, 60)
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	z, err := c.getHostedZoneName(fqdn)
	if err != nil {
		klog.Infof("Error getting hosted zone name for: %s, %v", fqdn, err)
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
		klog.Infof("Error getting hosted zone name for: %s, %v", fqdn, err)
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
		klog.Infof("Error creating TXT: %s, %v", z, err)
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
