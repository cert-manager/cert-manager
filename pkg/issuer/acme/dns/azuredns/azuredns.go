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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	dns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	privatedns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/go-logr/logr"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers  []string
	recordClient      RecordsClient
	zoneClient        ZonesClient
	resourceGroupName string
	zoneName          string
	log               logr.Logger
	zoneType          cmacme.AzureZoneType
}

// TODO:(@hjoshi123) change all arguments of NewDNSProviderCredentials to use variadic functions
type ProviderOption func(*DNSProvider)

// WithAzureZone is a provider option for specifying the type of Azure DNS zone (public or private) to be used by the DNSProvider.
func WithAzureZone(zone cmacme.AzureZoneType) ProviderOption {
	return func(d *DNSProvider) {
		d.zoneType = zone
	}
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Azure
// DNS service using static credentials from its parameters
func NewDNSProviderCredentials(environment, clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName string, dns01Nameservers []string, ambient bool, managedIdentity *cmacme.AzureManagedIdentity, opts ...ProviderOption) (*DNSProvider, error) {
	cloudCfg, err := getCloudConfiguration(environment)
	if err != nil {
		return nil, err
	}

	clientOpt := policy.ClientOptions{Cloud: cloudCfg}
	cred, err := getAuthorization(clientOpt, clientID, clientSecret, tenantID, ambient, managedIdentity)
	if err != nil {
		return nil, err
	}

	provider := &DNSProvider{
		dns01Nameservers:  dns01Nameservers,
		resourceGroupName: resourceGroupName,
		zoneName:          zoneName,
		log:               logf.Log.WithName("azure-dns"),
	}

	for _, opt := range opts {
		opt(provider)
	}

	if provider.zoneType == cmacme.PrivateAzureZone {
		rc, err := privatedns.NewRecordSetsClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}
		provider.recordClient = NewPrivateRecordsClient(rc)

		zc, err := privatedns.NewPrivateZonesClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}
		provider.zoneClient = NewPrivateZonesClient(zc)
	} else {
		rc, err := dns.NewRecordSetsClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}
		provider.recordClient = NewPublicRecordsClient(rc)

		zc, err := dns.NewZonesClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}
		provider.zoneClient = NewPublicZonesClient(zc)
	}

	return provider, nil
}

func getCloudConfiguration(name string) (cloud.Configuration, error) {
	switch strings.ToUpper(name) {
	case "AZURECLOUD", "AZUREPUBLICCLOUD", "":
		return cloud.AzurePublic, nil
	case "AZUREUSGOVERNMENT", "AZUREUSGOVERNMENTCLOUD":
		return cloud.AzureGovernment, nil
	case "AZURECHINACLOUD":
		return cloud.AzureChina, nil
	}
	return cloud.Configuration{}, fmt.Errorf("unknown cloud configuration name: %s", name)
}

func getAuthorization(clientOpt policy.ClientOptions, clientID, clientSecret, tenantID string, ambient bool, managedIdentity *cmacme.AzureManagedIdentity) (azcore.TokenCredential, error) {
	if clientID != "" {
		logf.Log.V(logf.InfoLevel).Info("azuredns authenticating with clientID and secret key")
		cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, &azidentity.ClientSecretCredentialOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}
		return cred, nil
	}

	logf.Log.V(logf.InfoLevel).Info("No ClientID found: attempting to authenticate with ambient credentials (Azure Workload Identity or Azure Managed Service Identity, in that order)")
	if !ambient {
		return nil, fmt.Errorf("ClientID was omitted without providing one of `--cluster-issuer-ambient-credentials` or `--issuer-ambient-credentials`. These are necessary to enable Azure Managed Identities")
	}

	// Use Workload Identity if present
	if os.Getenv("AZURE_FEDERATED_TOKEN_FILE") != "" {
		wcOpt := &azidentity.WorkloadIdentityCredentialOptions{
			ClientOptions: clientOpt,
		}
		if managedIdentity != nil {
			if managedIdentity.ClientID != "" {
				wcOpt.ClientID = managedIdentity.ClientID
			}
			if managedIdentity.TenantID != "" {
				wcOpt.TenantID = managedIdentity.TenantID
			}
		}

		return azidentity.NewWorkloadIdentityCredential(wcOpt)
	}

	logf.Log.V(logf.InfoLevel).Info("No Azure Workload Identity found: attempting to authenticate with an Azure Managed Service Identity (MSI)")

	msiOpt := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: clientOpt}
	if managedIdentity != nil {
		if managedIdentity.ClientID != "" {
			msiOpt.ID = azidentity.ClientID(managedIdentity.ClientID)
		}
		if managedIdentity.ResourceID != "" {
			msiOpt.ID = azidentity.ResourceID(managedIdentity.ResourceID)
		}
	}

	cred, err := azidentity.NewManagedIdentityCredential(msiOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to create the managed service identity token: %w", err)
	}
	return cred, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	return c.updateTXTRecord(ctx, fqdn, func(set RecordSet) {
		var found bool
		txtRecords := set.GetTXTRecords()
		for _, r := range txtRecords {
			if len(r) > 0 && *r[0] == value {
				found = true
				break
			}
		}

		if !found {
			txtRecords = append(txtRecords, []*string{
				to.Ptr(value),
			})
			set.SetTXTRecords(txtRecords)
		}
	})
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	return c.updateTXTRecord(ctx, fqdn, func(set RecordSet) {
		txtRecords := set.GetTXTRecords()
		records := make([][]*string, 0, len(txtRecords))
		for _, r := range txtRecords {
			if len(r) > 0 && *r[0] != value {
				records = append(records, r)
			}
		}

		set.SetTXTRecords(records)
	})
}

func (c *DNSProvider) getHostedZoneName(ctx context.Context, fqdn string) (string, error) {
	if c.zoneName != "" {
		return c.zoneName, nil
	}
	z, err := util.FindZoneByFqdn(ctx, fqdn, c.dns01Nameservers)
	if err != nil {
		return "", err
	}
	if len(z) == 0 {
		return "", fmt.Errorf("Zone %s not found for domain %s", z, fqdn)
	}

	if err := c.zoneClient.Get(ctx, c.resourceGroupName, util.UnFqdn(z), nil); err != nil {
		c.log.Error(err, "Error getting Zone for domain", "zone", z, "domain", fqdn, "resource group", c.resourceGroupName)
		return "", fmt.Errorf("Zone %s not found in AzureDNS for domain %s. Err: %w", z, fqdn, err)
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

// Updates or removes DNS TXT record while respecting optimistic concurrency control
func (c *DNSProvider) updateTXTRecord(ctx context.Context, fqdn string, updater func(RecordSet)) error {
	zone, err := c.getHostedZoneName(ctx, fqdn)
	if err != nil {
		return err
	}

	name := c.trimFqdn(fqdn, zone)

	var set RecordSet

	resp, err := c.recordClient.Get(ctx, c.resourceGroupName, zone, name, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr); respErr != nil && respErr.StatusCode == http.StatusNotFound {
			// Conditional initialization to avoid nil pointer
			if c.zoneType == cmacme.PrivateAzureZone {
				set = &PrivateTXTRecordSet{
					RS: &privatedns.RecordSet{
						Properties: &privatedns.RecordSetProperties{
							TTL:        to.Ptr[int64](60),
							TxtRecords: []*privatedns.TxtRecord{},
						},
						Etag: to.Ptr(""),
					},
				}
			} else {
				set = &PublicTXTRecordSet{
					RS: &dns.RecordSet{
						Properties: &dns.RecordSetProperties{
							TTL:        to.Ptr[int64](60),
							TxtRecords: []*dns.TxtRecord{},
						},
						Etag: to.Ptr(""),
					},
				}
			}
		} else {
			c.log.Error(err, "Error reading TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
			return err
		}
	} else {
		set = resp
	}

	updater(set)

	if len(set.GetTXTRecords()) == 0 {
		if etag := set.GetETag(); etag != nil && *etag != "" {
			// Etag will cause the deletion to fail if any updates happen concurrently
			err = c.recordClient.Delete(ctx, c.resourceGroupName, zone, name, &ClientOptions{IfMatch: set.GetETag()})
			if err != nil {
				c.log.Error(err, "Error deleting TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
				return err
			}
		}

		return nil
	}

	opts := &ClientOptions{}
	if etag := set.GetETag(); etag != nil && *etag == "" {
		// This is used to indicate that we want the API call to fail if a conflicting record was created concurrently
		// Only relevant when this is a new record, for updates conflicts are solved with Etag
		opts.IfNoneMatch = to.Ptr("*")
	} else {
		opts.IfMatch = set.GetETag()
	}

	_, err = c.recordClient.CreateOrUpdate(
		ctx,
		c.resourceGroupName,
		zone,
		name,
		set,
		opts)
	if err != nil {
		c.log.Error(err, "Error upserting TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
		return err
	}

	return nil
}
