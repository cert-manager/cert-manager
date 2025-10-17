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
	dns01Nameservers    []string
	recordClient        *dns.RecordSetsClient
	privateRecordClient PrivateRecordsClient
	zoneClient          *dns.ZonesClient
	privateZoneClient   PrivateZonesClient
	resourceGroupName   string
	zoneName            string
	log                 logr.Logger
	isPrivateZone       bool
}

type ProviderOption func(*DNSProvider)

func WithPrivateZone(isPrivateZone bool) ProviderOption {
	return func(c *DNSProvider) {
		c.isPrivateZone = isPrivateZone
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

	if provider.isPrivateZone {
		rc, err := privatedns.NewRecordSetsClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}

		zc, err := privatedns.NewPrivateZonesClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}

		provider.privateRecordClient = rc
		provider.privateZoneClient = zc
	} else {
		rc, err := dns.NewRecordSetsClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}
		zc, err := dns.NewZonesClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
		if err != nil {
			return nil, err
		}

		provider.recordClient = rc
		provider.zoneClient = zc
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
		return nil, fmt.Errorf("failed to create the managed service identity token: %v", err)
	}
	return cred, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	return c.updateTXTRecord(ctx, fqdn, func(set TXTRecordSet) {
		var found bool
		for _, r := range set.GetTXTRecords() {
			if len(r) > 0 && *r[0] == value {
				found = true
				break
			}
		}

		if !found {
			set.AppendTXTRecord(value)
		}
	})
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	return c.updateTXTRecord(ctx, fqdn, func(set TXTRecordSet) {
		for _, r := range set.GetTXTRecords() {
			if len(r) > 0 && *r[0] != value {
				set.AppendTXTRecord(value)
			}
		}
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

	if c.isPrivateZone {
		_, err = c.privateZoneClient.Get(ctx, c.resourceGroupName, util.UnFqdn(z), nil)
	} else {
		_, err = c.zoneClient.Get(ctx, c.resourceGroupName, util.UnFqdn(z), nil)
	}

	if err != nil {
		c.log.Error(err, "Error getting Zone for domain", "zone", z, "domain", fqdn, "resource group", c.resourceGroupName)
		return "", fmt.Errorf("Zone %s not found in AzureDNS for domain %s. Err: %v", z, fqdn, stabilizeError(err))
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
func (c *DNSProvider) updateTXTRecord(ctx context.Context, fqdn string, updater func(TXTRecordSet)) error {
	zone, err := c.getHostedZoneName(ctx, fqdn)
	if err != nil {
		return err
	}

	name := c.trimFqdn(fqdn, zone)

	if c.isPrivateZone {
		return c.updatePrivateTXTRecord(ctx, fqdn, name, zone, updater)
	}

	publicTXTRecordSet := new(PublicTXTRecordSet)
	resp, err := c.recordClient.Get(ctx, c.resourceGroupName, zone, name, dns.RecordTypeTXT, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		err = c.handleResponseError(err, zone, fqdn)
		if errors.As(err, &respErr) {
			publicTXTRecordSet.RS = &dns.RecordSet{
				Properties: &dns.RecordSetProperties{
					TTL:        to.Ptr(int64(60)),
					TxtRecords: []*dns.TxtRecord{},
				},
				Etag: to.Ptr(""),
			}
		} else {
			return err
		}
	} else {
		publicTXTRecordSet.RS = &resp.RecordSet
	}

	updater(publicTXTRecordSet)

	set := publicTXTRecordSet.RS
	if len(set.Properties.TxtRecords) == 0 {
		if *set.Etag != "" {
			// Etag will cause the deletion to fail if any updates happen concurrently
			_, err = c.recordClient.Delete(ctx, c.resourceGroupName, zone, name, dns.RecordTypeTXT, &dns.RecordSetsClientDeleteOptions{IfMatch: set.Etag})
			if err != nil {
				c.log.Error(err, "Error deleting TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
				return stabilizeError(err)
			}
		}

		return nil
	}

	opts := &dns.RecordSetsClientCreateOrUpdateOptions{}
	if *set.Etag == "" {
		// This is used to indicate that we want the API call to fail if a conflicting record was created concurrently
		// Only relevant when this is a new record, for updates conflicts are solved with Etag
		opts.IfNoneMatch = to.Ptr("*")
	} else {
		opts.IfMatch = set.Etag
	}

	_, err = c.recordClient.CreateOrUpdate(
		ctx,
		c.resourceGroupName,
		zone,
		name,
		dns.RecordTypeTXT,
		*set,
		opts)
	if err != nil {
		c.log.Error(err, "Error upserting TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
		return stabilizeError(err)
	}

	return nil
}

func (c *DNSProvider) updatePrivateTXTRecord(ctx context.Context, fqdn, name, zone string, updater func(TXTRecordSet)) error {
	privateRecordTXTSet := new(PrivateTXTRecordSet)
	resp, err := c.privateRecordClient.Get(ctx, c.resourceGroupName, zone, privatedns.RecordTypeTXT, name, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		err = c.handleResponseError(err, zone, fqdn)
		if errors.As(err, &respErr) {
			privateRecordTXTSet.RS = &privatedns.RecordSet{
				Properties: &privatedns.RecordSetProperties{
					TTL:        to.Ptr(int64(60)),
					TxtRecords: []*privatedns.TxtRecord{},
				},
				Etag: to.Ptr(""),
			}
		} else {
			return err
		}
	} else {
		privateRecordTXTSet.RS = &resp.RecordSet
	}

	updater(privateRecordTXTSet)

	set := privateRecordTXTSet.RS
	if len(set.Properties.TxtRecords) == 0 {
		if *set.Etag != "" {
			// Etag will cause the deletion to fail if any updates happen concurrently
			_, err = c.privateRecordClient.Delete(ctx, c.resourceGroupName, zone, privatedns.RecordTypeTXT, name, &privatedns.RecordSetsClientDeleteOptions{IfMatch: set.Etag})
			if err != nil {
				c.log.Error(err, "Error deleting TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
				return stabilizeError(err)
			}
		}

		return nil
	}

	opts := &privatedns.RecordSetsClientCreateOrUpdateOptions{}
	if *set.Etag == "" {
		// This is used to indicate that we want the API call to fail if a conflicting record was created concurrently
		// Only relevant when this is a new record, for updates conflicts are solved with Etag
		opts.IfNoneMatch = to.Ptr("*")
	} else {
		opts.IfMatch = set.Etag
	}

	_, err = c.privateRecordClient.CreateOrUpdate(
		ctx,
		c.resourceGroupName,
		zone,
		privatedns.RecordTypeTXT,
		name,
		*set,
		opts)
	if err != nil {
		c.log.Error(err, "Error upserting TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
		return stabilizeError(err)
	}

	return nil
}

func (c *DNSProvider) handleResponseError(err error, zone, fqdn string) error {
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr); respErr != nil && respErr.StatusCode == http.StatusNotFound {
			return respErr
		} else {
			c.log.Error(err, "Error reading TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
			return stabilizeError(err)
		}
	}

	return nil
}

// The azure-sdk library returns the contents of the HTTP requests in its
// error messages. We want our error messages to be the same when the cause
// is the same to avoid spurious challenge updates.
//
// The given error must not be nil. This function must be called everywhere
// we have a non-nil error coming from an azure-sdk func that makes API calls.
func stabilizeError(err error) error {
	if err == nil {
		return nil
	}

	return NormalizedError{
		Cause: err,
	}
}

type NormalizedError struct {
	Cause error
}

func (e NormalizedError) Error() string {
	var (
		authErr *azidentity.AuthenticationFailedError
		respErr *azcore.ResponseError
	)

	switch {
	case errors.As(e.Cause, &authErr):
		msg := new(strings.Builder)
		fmt.Fprintln(msg, "authentication failed:")

		if authErr.RawResponse != nil {
			if authErr.RawResponse.Request != nil {
				fmt.Fprintf(msg, "%s %s://%s%s\n", authErr.RawResponse.Request.Method, authErr.RawResponse.Request.URL.Scheme, authErr.RawResponse.Request.URL.Host, authErr.RawResponse.Request.URL.Path)
			}

			fmt.Fprintln(msg, "--------------------------------------------------------------------------------")
			fmt.Fprintf(msg, "RESPONSE %s\n", authErr.RawResponse.Status)
			fmt.Fprintln(msg, "--------------------------------------------------------------------------------")
		}

		fmt.Fprint(msg, "see logs for more information")

		return msg.String()
	case errors.As(e.Cause, &respErr):
		msg := new(strings.Builder)
		fmt.Fprintln(msg, "request error:")

		if respErr.RawResponse != nil {
			if respErr.RawResponse.Request != nil {
				fmt.Fprintf(msg, "%s %s://%s%s\n", respErr.RawResponse.Request.Method, respErr.RawResponse.Request.URL.Scheme, respErr.RawResponse.Request.URL.Host, respErr.RawResponse.Request.URL.Path)
			}

			fmt.Fprintln(msg, "--------------------------------------------------------------------------------")
			fmt.Fprintf(msg, "RESPONSE %s\n", respErr.RawResponse.Status)
			if respErr.ErrorCode != "" {
				fmt.Fprintf(msg, "ERROR CODE: %s\n", respErr.ErrorCode)
			} else {
				fmt.Fprintln(msg, "ERROR CODE UNAVAILABLE")
			}
			fmt.Fprintln(msg, "--------------------------------------------------------------------------------")
		}

		fmt.Fprint(msg, "see logs for more information")

		return msg.String()

	default:
		return e.Cause.Error()
	}
}
