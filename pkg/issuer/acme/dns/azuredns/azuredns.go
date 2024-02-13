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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/logr"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	dns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"

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
		dns.RecordTypeTXT, nil)
	if err != nil {
		c.log.Error(err, "Error deleting TXT", "zone", z, "domain", fqdn, "resource group", c.resourceGroupName)
		return stabilizeError(err)
	}
	return nil
}

func (c *DNSProvider) createRecord(fqdn, value string, ttl int) error {
	rparams := &dns.RecordSet{
		Properties: &dns.RecordSetProperties{
			TTL: to.Ptr(int64(ttl)),
			TxtRecords: []*dns.TxtRecord{
				{Value: []*string{&value}},
			},
		},
	}

	z, err := c.getHostedZoneName(fqdn)
	if err != nil {
		return err
	}

	_, err = c.recordClient.CreateOrUpdate(
		context.TODO(),
		c.resourceGroupName,
		z,
		c.trimFqdn(fqdn, z),
		dns.RecordTypeTXT,
		*rparams, nil)
	if err != nil {
		c.log.Error(err, "Error creating TXT", "zone", z, "domain", fqdn, "resource group", c.resourceGroupName)
		return stabilizeError(err)
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

	if _, err := c.zoneClient.Get(context.TODO(), c.resourceGroupName, util.UnFqdn(z), nil); err != nil {
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

// The azure-sdk library returns the contents of the HTTP requests in its
// error messages. We want our error messages to be the same when the cause
// is the same to avoid spurious challenge updates.
//
// The given error must not be nil. This function must be called everywhere
// we have a non-nil error coming from a azure-sdk func that makes API calls.
func stabilizeError(err error) error {
	if err == nil {
		return nil
	}

	redactResponse := func(resp *http.Response) *http.Response {
		if resp == nil {
			return nil
		}

		reponse := *resp
		reponse.Body = io.NopCloser(bytes.NewReader([]byte("<REDACTED>")))
		return &reponse
	}

	var authErr *azidentity.AuthenticationFailedError
	if errors.As(err, &authErr) {
		authErr.RawResponse = redactResponse(authErr.RawResponse)
	}

	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		respErr.RawResponse = redactResponse(respErr.RawResponse)
	}

	return err
}
