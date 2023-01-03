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
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/logr"

	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2017-10-01/dns"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
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
func NewDNSProviderCredentials(environment, clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName string, dns01Nameservers []string, ambient bool, managedIdentity *cmacme.AzureManagedIdentity) (*DNSProvider, error) {
	env := azure.PublicCloud
	if environment != "" {
		var err error
		env, err = azure.EnvironmentFromName(environment)
		if err != nil {
			return nil, err
		}
	}

	spt, err := getAuthorization(env, clientID, clientSecret, subscriptionID, tenantID, ambient, managedIdentity)
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

// Implements adal.TokenRefreshError
type tokenRefreshError struct {
	Message string
	Resp    *http.Response
}

func (tre tokenRefreshError) Error() string {
	return tre.Message
}

func (tre tokenRefreshError) Response() *http.Response {
	return tre.Resp
}

// suppressMessageInTokenRefreshError can be used to suppress error message contents in adal.TokenRefreshError to prevent early
// reconciliations in controller due to CR status updates with unique data (such as timestamp, Trace ID) present in response body
func suppressMessageInTokenRefreshError(originalError error) error {
	if originalError == nil {
		return nil
	}

	// No need to overwrite errors of another type
	tre, ok := originalError.(adal.TokenRefreshError)
	if !ok {
		return originalError
	}

	err := tokenRefreshError{
		Message: "failed to refresh token",
		Resp:    tre.Response(),
	}

	return err
}

// getFederatedSPT prepares an SPT for a Workload Identity-enabled setup
func getFederatedSPT(env azure.Environment, options adal.ManagedIdentityOptions) (*adal.ServicePrincipalToken, error) {
	// NOTE: all related environment variables are described here: https://azure.github.io/azure-workload-identity/docs/installation/mutating-admission-webhook.html
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, os.Getenv("AZURE_TENANT_ID"))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve OAuth config: %v", err)
	}

	jwt, err := os.ReadFile(os.Getenv("AZURE_FEDERATED_TOKEN_FILE"))
	if err != nil {
		return nil, fmt.Errorf("failed to read a file with a federated token: %v", err)
	}

	// AZURE_CLIENT_ID will be empty in case azure.workload.identity/client-id annotation is not set
	// Also, some users might want to use a different MSI for a particular DNS zone
	// Thus, it's important to offer optional ClientID overrides
	clientID := os.Getenv("AZURE_CLIENT_ID")
	if options.ClientID != "" {
		clientID = options.ClientID
	}

	token, err := adal.NewServicePrincipalTokenFromFederatedToken(*oauthConfig, clientID, string(jwt), env.ResourceManagerEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create a workload identity token: %v", err)
	}

	return token, nil
}

func getAuthorization(env azure.Environment, clientID, clientSecret, subscriptionID, tenantID string, ambient bool, managedIdentity *cmacme.AzureManagedIdentity) (*adal.ServicePrincipalToken, error) {
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
	logf.Log.V(logf.InfoLevel).Info("No ClientID found: attempting to authenticate with ambient credentials (Azure Workload Identity or Azure Managed Service Identity, in that order)")
	if !ambient {
		return nil, fmt.Errorf("ClientID is not set but neither `--cluster-issuer-ambient-credentials` nor `--issuer-ambient-credentials` are set. These are necessary to enable Azure Managed Identities")
	}

	opt := adal.ManagedIdentityOptions{}

	if managedIdentity != nil {
		opt.ClientID = managedIdentity.ClientID
		opt.IdentityResourceID = managedIdentity.ResourceID
	}

	// Use Workload Identity if present
	if os.Getenv("AZURE_FEDERATED_TOKEN_FILE") != "" {
		spt, err := getFederatedSPT(env, opt)
		if err != nil {
			return nil, err
		}

		// adal does not offer methods to dynamically replace a federated token, thus we need to have a wrapper to make sure
		// we're using up-to-date secret while requesting an access token.
		// NOTE: There's no RefreshToken in the whole process (in fact, it's absent in AAD responses). An AccessToken can be
		// received only in exchange for a federated token.
		var refreshFunc adal.TokenRefresh = func(context context.Context, resource string) (*adal.Token, error) {
			newSPT, err := getFederatedSPT(env, opt)
			if err != nil {
				return nil, err
			}

			// An AccessToken gets populated into an spt only when .Refresh() is called. Normally, it's something that happens implicitly when
			// a first request to manipulate Azure resources is made. Since our goal here is only to receive a fresh AccessToken, we need to make
			// an explicit call.
			// .Refresh() itself results in a call to Oauth endpoint. During the process, a federated token is exchanged for an AccessToken.
			// RefreshToken is absent from responses.
			err = newSPT.Refresh()
			if err != nil {
				logf.Log.V(logf.ErrorLevel).Error(err, "failed to refresh token")
				return nil, suppressMessageInTokenRefreshError(err)
			}

			accessToken := newSPT.Token()

			return &accessToken, nil
		}

		spt.SetCustomRefreshFunc(refreshFunc)

		return spt, nil
	}

	logf.Log.V(logf.InfoLevel).Info("No Azure Workload Identity found: attempting to authenticate with an Azure Managed Service Identity (MSI)")

	spt, err := adal.NewServicePrincipalTokenFromManagedIdentity(env.ServiceManagementEndpoint, &opt)
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
