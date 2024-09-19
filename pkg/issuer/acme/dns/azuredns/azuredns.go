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
	"github.com/go-logr/logr"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers  []string
	recordClient      *dns.RecordSetsClient
	zoneClient        *dns.ZonesClient
	resourceGroupName string
	zoneName          string
	log               logr.Logger
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Azure
// DNS service using static credentials from its parameters
func NewDNSProviderCredentials(environment, clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName string, dns01Nameservers []string, ambient bool, managedIdentity *cmacme.AzureManagedIdentity) (*DNSProvider, error) {
	cloudCfg, err := getCloudConfiguration(environment)
	if err != nil {
		return nil, err
	}

	clientOpt := policy.ClientOptions{Cloud: cloudCfg}
	cred, err := getAuthorization(clientOpt, clientID, clientSecret, tenantID, ambient, managedIdentity)
	if err != nil {
		return nil, err
	}
	rc, err := dns.NewRecordSetsClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
	if err != nil {
		return nil, err
	}
	zc, err := dns.NewZonesClient(subscriptionID, cred, &arm.ClientOptions{ClientOptions: clientOpt})
	if err != nil {
		return nil, err
	}

	return &DNSProvider{
		dns01Nameservers:  dns01Nameservers,
		recordClient:      rc,
		zoneClient:        zc,
		resourceGroupName: resourceGroupName,
		zoneName:          zoneName,
		log:               logf.Log.WithName("azure-dns"),
	}, nil
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
		return nil, fmt.Errorf("ClientID is not set but neither `--cluster-issuer-ambient-credentials` nor `--issuer-ambient-credentials` are set. These are necessary to enable Azure Managed Identities")
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
	return c.updateTXTRecord(ctx, fqdn, func(set *dns.RecordSet) {
		var found bool
		for _, r := range set.Properties.TxtRecords {
			if len(r.Value) > 0 && *r.Value[0] == value {
				found = true
				break
			}
		}

		if !found {
			set.Properties.TxtRecords = append(set.Properties.TxtRecords, &dns.TxtRecord{
				Value: []*string{to.Ptr(value)},
			})
		}
	})
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	return c.updateTXTRecord(ctx, fqdn, func(set *dns.RecordSet) {
		var records []*dns.TxtRecord
		for _, r := range set.Properties.TxtRecords {
			if len(r.Value) > 0 && *r.Value[0] != value {
				records = append(records, r)
			}
		}

		set.Properties.TxtRecords = records
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

	if _, err := c.zoneClient.Get(ctx, c.resourceGroupName, util.UnFqdn(z), nil); err != nil {
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
func (c *DNSProvider) updateTXTRecord(ctx context.Context, fqdn string, updater func(*dns.RecordSet)) error {
	zone, err := c.getHostedZoneName(ctx, fqdn)
	if err != nil {
		return err
	}

	name := c.trimFqdn(fqdn, zone)

	var set *dns.RecordSet

	resp, err := c.recordClient.Get(ctx, c.resourceGroupName, zone, name, dns.RecordTypeTXT, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr); respErr != nil && respErr.StatusCode == http.StatusNotFound {
			set = &dns.RecordSet{
				Properties: &dns.RecordSetProperties{
					TTL:        to.Ptr(int64(60)),
					TxtRecords: []*dns.TxtRecord{},
				},
				Etag: to.Ptr(""),
			}
		} else {
			c.log.Error(err, "Error reading TXT", "zone", zone, "domain", fqdn, "resource group", c.resourceGroupName)
			return stabilizeError(err)
		}
	} else {
		set = &resp.RecordSet
	}

	updater(set)

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
