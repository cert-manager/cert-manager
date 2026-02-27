// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package azuredns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	dns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	privatedns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	azureLiveTest          bool
	azureClientID          string
	azureClientSecret      string
	azuresubscriptionID    string
	azureTenantID          string
	azureResourceGroupName string
	azureHostedZoneName    string
	azureDomain            string
)

func init() {
	azureClientID = os.Getenv("AZURE_CLIENT_ID")
	azureClientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	azuresubscriptionID = os.Getenv("AZURE_SUBSCRIPTION_ID")
	azureTenantID = os.Getenv("AZURE_TENANT_ID")
	azureResourceGroupName = os.Getenv("AZURE_RESOURCE_GROUP")
	azureHostedZoneName = os.Getenv("AZURE_ZONE_NAME")
	azureDomain = os.Getenv("AZURE_DOMAIN")
	if len(azureClientID) > 0 && len(azureClientSecret) > 0 && len(azureDomain) > 0 {
		azureLiveTest = true
	}
}

type fakePublicZonesClient struct {
	zones map[string]dns.Zone
}

func newFakePublicZonesClient(zones map[string]dns.Zone) ZonesClient {
	return &fakePublicZonesClient{zones: zones}
}

func (fpz *fakePublicZonesClient) Get(ctx context.Context, resourceGroupName string, zoneName string, options *ClientOptions) error {
	_, ok := fpz.zones[zoneName]
	if !ok {
		return errors.New("no zone found")
	}

	return nil
}

type fakePublicRecordsClient struct {
	records map[string]RecordSet
}

func newFakeRecordSetsClient(records map[string]RecordSet) RecordsClient {
	return &fakePublicRecordsClient{records: records}
}

func (fpr *fakePublicRecordsClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, set RecordSet, options *ClientOptions) (RecordSet, error) {
	key := fmt.Sprintf("%s.%s", relativeRecordSetName, zoneName)
	fpr.records[key] = set
	return set, nil
}

func (fpr *fakePublicRecordsClient) Get(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, options *ClientOptions) (RecordSet, error) {
	key := fmt.Sprintf("%s.%s", relativeRecordSetName, zoneName)
	r, ok := fpr.records[key]
	if !ok {
		return nil, errors.New("no record found")
	}

	return r, nil
}

func (fpr *fakePublicRecordsClient) Delete(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, options *ClientOptions) error {
	if len(fpr.records) == 0 {
		return nil
	}
	delete(fpr.records, fmt.Sprintf("%s.%s", relativeRecordSetName, zoneName))
	return nil
}

type fakePrivateZonesClient struct {
	zones map[string]dns.Zone
}

func newFakePrivateZonesClient(zones map[string]dns.Zone) ZonesClient {
	return &fakePrivateZonesClient{zones: zones}
}

func (fpz *fakePrivateZonesClient) Get(ctx context.Context, resourceGroupName string, zoneName string, options *ClientOptions) error {
	_, ok := fpz.zones[zoneName]
	if !ok {
		return errors.New("no zone found")
	}

	return nil
}

type fakePrivateRecordsClient struct {
	records map[string]RecordSet
}

func newFakePrivateRecordSetsClient(records map[string]RecordSet) RecordsClient {
	return &fakePrivateRecordsClient{records: records}
}

func (fpr *fakePrivateRecordsClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, set RecordSet, options *ClientOptions) (RecordSet, error) {
	key := fmt.Sprintf("%s.%s", relativeRecordSetName, zoneName)
	fpr.records[key] = set
	return set, nil
}

func (fpr *fakePrivateRecordsClient) Get(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, options *ClientOptions) (RecordSet, error) {
	key := fmt.Sprintf("%s.%s", relativeRecordSetName, zoneName)
	r, ok := fpr.records[key]
	if !ok {
		return nil, errors.New("no record found")
	}

	return r, nil
}

func (fpr *fakePrivateRecordsClient) Delete(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, options *ClientOptions) error {
	if len(fpr.records) == 0 {
		return nil
	}
	delete(fpr.records, fmt.Sprintf("%s.%s", relativeRecordSetName, zoneName))
	return nil
}

func TestLiveAzureDnsPresent(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.Present(t.Context(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveAzureDnsPresentMultiple(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.Present(t.Context(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
	err = provider.Present(t.Context(), azureDomain, "_acme-challenge."+azureDomain+".", "1123d==")
	assert.NoError(t, err)
}

func TestLiveAzureDnsCleanUp(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 5)

	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.CleanUp(t.Context(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveAzureDnsCleanUpMultiple(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 10)

	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.CleanUp(t.Context(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
	err = provider.CleanUp(t.Context(), azureDomain, "_acme-challenge."+azureDomain+".", "1123d==")
	assert.NoError(t, err)
}

func TestInvalidAzureDns(t *testing.T) {
	validEnv := []string{"", "AzurePublicCloud", "AzureChinaCloud", "AzureUSGovernmentCloud"}
	for _, env := range validEnv {
		_, err := NewDNSProviderCredentials(env, "cid", "secret", "", "tenid", "", "", util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
		assert.NoError(t, err)
	}

	// Invalid environment
	_, err := NewDNSProviderCredentials("invalid env", "cid", "secret", "", "tenid", "", "", util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.Error(t, err)

	// Invalid tenantID
	_, err = NewDNSProviderCredentials("", "cid", "secret", "", "invalid env value", "", "", util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.Error(t, err)
}

func TestAuthenticationError(t *testing.T) {
	provider, err := NewDNSProviderCredentials("", "invalid-client-id", "invalid-client-secret", "subid", "tenid", "rg", "example.com", util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "123d==")
	assert.Error(t, err)

	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.", "123d==")
	assert.Error(t, err)
}

func populateFederatedToken(t *testing.T, filename string, content string) {
	t.Helper()

	// #nosec G703 -- test code creating a file, safe from path traversal
	f, err := os.Create(filename)
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	if _, err := io.WriteString(f, content); err != nil {
		assert.FailNow(t, err.Error())
	}

	if err := f.Close(); err != nil {
		assert.FailNow(t, err.Error())
	}
}

func TestGetAuthorizationFederatedSPT(t *testing.T) {
	// Create a file that will be used to store a federated token
	f, err := os.CreateTemp(t.TempDir(), "")
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	// Close the file to simplify logic within populateFederatedToken helper
	if err := f.Close(); err != nil {
		assert.FailNow(t, err.Error())
	}

	// The initial federated token is never used, so we don't care about the value yet
	// Though, it's a requirement from adal to have a non-empty value set
	populateFederatedToken(t, f.Name(), "random-jwt")

	// Prepare environment variables adal will rely on. Skip changes for some envs if they are already defined (=live environment)
	// Envs themselves are described here: https://azure.github.io/azure-workload-identity/docs/installation/mutating-admission-webhook.html
	if os.Getenv("AZURE_TENANT_ID") == "" {
		// TODO(wallrj): This is a hack. It is a quick way to `DisableInstanceDiscovery` during tests,
		// to avoid the client attempting to connect to https://login.microsoftonline.com/common/discovery/instance.
		// It works because there is a special case in azure-sdk-for-go which
		// disables the instance discovery when the tenant ID is `adfs`. See:
		// https://github.com/Azure/azure-sdk-for-go/blob/7288bda422654bde520a09034dd755b8f2dd4168/sdk/azidentity/public_client.go#L237-L239
		// https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview
		//
		// Find a better way to test this code.
		t.Setenv("AZURE_TENANT_ID", "adfs")
	}

	if os.Getenv("AZURE_CLIENT_ID") == "" {
		t.Setenv("AZURE_CLIENT_ID", "fakeClientID")
	}

	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", f.Name())

	t.Run("token refresh", func(t *testing.T) {
		// Basically, we want one token to be exchanged for the other (key and value respectively)
		tokens := map[string]string{
			"initialFederatedToken":   "initialAccessToken",
			"refreshedFederatedToken": "refreshedAccessToken",
		}

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				tenantURL := strings.TrimSuffix("https://"+r.Host+r.URL.Path, "/.well-known/openid-configuration")

				w.Header().Set("Content-Type", "application/json")
				openidConfiguration := map[string]string{
					"token_endpoint":         tenantURL + "/oauth2/token",
					"authorization_endpoint": tenantURL + "/oauth2/authorize",
					"issuer":                 tenantURL + "/adfs/",
				}

				if err := json.NewEncoder(w).Encode(openidConfiguration); err != nil {
					assert.FailNow(t, err.Error())
				}

				return
			}

			if err := r.ParseForm(); err != nil {
				assert.FailNow(t, err.Error())
			}

			w.Header().Set("Content-Type", "application/json")
			receivedFederatedToken := r.FormValue("client_assertion")
			accessToken := map[string]any{
				"access_token": tokens[receivedFederatedToken],
				// the Azure SDK will not use tokens that are within 5 minutes of their expiration
				// so "expires_on": time.Now().Add(4 * time.Minute) would work too
				"expires_on": time.Now().Add(-1 * time.Second),
			}

			if err := json.NewEncoder(w).Encode(accessToken); err != nil {
				assert.FailNow(t, err.Error())
			}

			// Expected format: http://<server>/<tenant-ID>/oauth2/token?api-version=1.0
			assert.Contains(t, r.RequestURI, strings.ToLower(os.Getenv("AZURE_TENANT_ID")), "URI should contain the tenant ID exposed through env variable")

			assert.Equal(t, os.Getenv("AZURE_CLIENT_ID"), r.FormValue("client_id"), "client_id should match the value exposed through env variable")
		}))
		defer ts.Close()

		ambient := true
		clientOpt := policy.ClientOptions{
			Cloud:     cloud.Configuration{ActiveDirectoryAuthorityHost: ts.URL},
			Transport: ts.Client(),
		}
		managedIdentity := &v1.AzureManagedIdentity{ClientID: ""}

		spt, err := getAuthorization(clientOpt, "", "", "", ambient, managedIdentity)
		assert.NoError(t, err)

		for federatedToken, accessToken := range tokens {
			populateFederatedToken(t, f.Name(), federatedToken)
			token, err := spt.GetToken(t.Context(), policy.TokenRequestOptions{Scopes: []string{"test"}})
			assert.NoError(t, err)
			assert.Equal(t, accessToken, token.Token, "Access token should have been set to a value returned by the webserver")

			// Overwrite the expires field to force the token to be re-read from disk.
			// Also, we set expires_on such that the token we got from the API has expired
			// already too.
			expiresField := reflect.
				ValueOf(spt.(*azidentity.WorkloadIdentityCredential)).
				Elem().
				FieldByName("expires")
			reflect.
				NewAt(expiresField.Type(), expiresField.Addr().UnsafePointer()).
				Elem().
				Set(reflect.ValueOf(time.Now().Add(-1 * time.Second)))
		}
	})

	t.Run("clientID overrides through managedIdentity section", func(t *testing.T) {
		managedIdentity := &v1.AzureManagedIdentity{ClientID: "anotherClientID"}

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				tenantURL := strings.TrimSuffix("https://"+r.Host+r.URL.Path, "/.well-known/openid-configuration")

				w.Header().Set("Content-Type", "application/json")
				openidConfiguration := map[string]string{
					"token_endpoint":         tenantURL + "/oauth2/token",
					"authorization_endpoint": tenantURL + "/oauth2/authorize",
					"issuer":                 tenantURL + "/adfs/",
				}

				if err := json.NewEncoder(w).Encode(openidConfiguration); err != nil {
					assert.FailNow(t, err.Error())
				}

				return
			}

			if err := r.ParseForm(); err != nil {
				assert.FailNow(t, err.Error())
			}

			w.Header().Set("Content-Type", "application/json")
			accessToken := map[string]any{
				"access_token": "abc",
				"expires_in":   500,
			}

			if err := json.NewEncoder(w).Encode(accessToken); err != nil {
				assert.FailNow(t, err.Error())
			}

			assert.Equal(t, managedIdentity.ClientID, r.FormValue("client_id"), "client_id should match the value passed through managedIdentity section")

			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		ambient := true
		clientOpt := policy.ClientOptions{
			Cloud:     cloud.Configuration{ActiveDirectoryAuthorityHost: ts.URL},
			Transport: ts.Client(),
		}

		spt, err := getAuthorization(clientOpt, "", "", "", ambient, managedIdentity)
		assert.NoError(t, err)

		token, err := spt.GetToken(t.Context(), policy.TokenRequestOptions{Scopes: []string{"test"}})
		assert.NoError(t, err)
		assert.NotEmpty(t, token.Token, "Access token should have been set to a value returned by the webserver")
	})
}

func TestMockAzurePublicDNSPresent(t *testing.T) {
	tests := []struct {
		name               string
		domain             string
		relativeRecordName string
		fqdn               string
		value              string
		expectError        bool
	}{
		{
			name:               "Present challenge in public zone",
			domain:             "test.internal.example.com",
			relativeRecordName: "_acme-challenge",
			fqdn:               "_acme-challenge.test.internal.example.com",
			value:              "validation-token-123",
			expectError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pzc := newFakePublicZonesClient(map[string]dns.Zone{
				tt.domain: {Name: &tt.domain},
			})
			recordSets := map[string]RecordSet{
				tt.fqdn: &PublicTXTRecordSet{
					RS: &dns.RecordSet{
						Name: &tt.fqdn,
						Etag: new(string),
						Properties: &dns.RecordSetProperties{
							TxtRecords: make([]*dns.TxtRecord, 0),
						},
					},
				},
			}
			prc := newFakeRecordSetsClient(recordSets)
			provider := &DNSProvider{
				recordClient:      prc,
				zoneClient:        pzc,
				resourceGroupName: "test-rg",
				zoneName:          "internal.example.com",
				log:               logrtesting.NewTestLogger(t),
			}

			err := provider.Present(t.Context(), tt.domain, tt.fqdn, tt.value)
			assert.NoError(t, err)
			val := *(recordSets[tt.fqdn].GetTXTRecords()[0][0])
			assert.Equal(t, tt.value, val)
		})
	}
}

func TestMockAzurePrivateDNSPresent(t *testing.T) {
	tests := []struct {
		name               string
		domain             string
		relativeRecordName string
		fqdn               string
		value              string
		expectError        bool
	}{
		{
			name:               "Present challenge in private zone",
			domain:             "test.internal.example.com",
			relativeRecordName: "_acme-challenge",
			fqdn:               "_acme-challenge.test.internal.example.com",
			value:              "validation-token-123",
			expectError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pzc := newFakePrivateZonesClient(map[string]dns.Zone{
				tt.domain: {Name: &tt.domain},
			})
			recordSets := map[string]RecordSet{
				tt.fqdn: &PrivateTXTRecordSet{
					RS: &privatedns.RecordSet{
						Name: &tt.fqdn,
						Etag: new(string),
						Properties: &privatedns.RecordSetProperties{
							TxtRecords: make([]*privatedns.TxtRecord, 0),
						},
					},
				},
			}
			prc := newFakePrivateRecordSetsClient(recordSets)
			provider := &DNSProvider{
				recordClient:      prc,
				zoneClient:        pzc,
				resourceGroupName: "test-rg",
				zoneName:          "internal.example.com",
				log:               logrtesting.NewTestLogger(t),
			}

			err := provider.Present(t.Context(), tt.domain, tt.fqdn, tt.value)
			assert.NoError(t, err)
			val := *(recordSets[tt.fqdn].GetTXTRecords()[0][0])
			assert.Equal(t, tt.value, val)
		})
	}
}

func TestMockAzurePublicDNSCleanUp(t *testing.T) {
	tests := []struct {
		name               string
		domain             string
		relativeRecordName string
		fqdn               string
		value              string
		expectError        bool
	}{
		{
			name:               "Cleanup entry in public zone",
			domain:             "test.internal.example.com",
			relativeRecordName: "_acme-challenge",
			fqdn:               "_acme-challenge.test.internal.example.com",
			value:              "validation-token-123",
			expectError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pzc := newFakePublicZonesClient(map[string]dns.Zone{
				tt.domain: {Name: &tt.domain},
			})
			recordSets := map[string]RecordSet{
				tt.fqdn: &PublicTXTRecordSet{
					RS: &dns.RecordSet{
						Name: &tt.fqdn,
						Etag: to.Ptr("etag-123"),
						Properties: &dns.RecordSetProperties{
							TxtRecords: []*dns.TxtRecord{
								{
									Value: []*string{to.Ptr("validation-token-123")},
								},
							},
						},
					},
				},
			}
			prc := newFakeRecordSetsClient(recordSets)
			provider := &DNSProvider{
				recordClient:      prc,
				zoneClient:        pzc,
				resourceGroupName: "test-rg",
				zoneName:          "internal.example.com",
				log:               logrtesting.NewTestLogger(t),
			}

			assert.Equal(t, len(recordSets[tt.fqdn].GetTXTRecords()), 1)
			err := provider.CleanUp(t.Context(), tt.domain, tt.fqdn, tt.value)
			assert.NoError(t, err)
			assert.Equal(t, len(recordSets), 0)
		})
	}
}

func TestMockAzurePrivateDNSCleanUp(t *testing.T) {
	tests := []struct {
		name               string
		domain             string
		relativeRecordName string
		fqdn               string
		value              string
		expectError        bool
	}{
		{
			name:               "Cleanup entry in private zone",
			domain:             "test.internal.example.com",
			relativeRecordName: "_acme-challenge",
			fqdn:               "_acme-challenge.test.internal.example.com",
			value:              "validation-token-123",
			expectError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pzc := newFakePrivateZonesClient(map[string]dns.Zone{
				tt.domain: {Name: &tt.domain},
			})
			recordSets := map[string]RecordSet{
				tt.fqdn: &PrivateTXTRecordSet{
					RS: &privatedns.RecordSet{
						Name: &tt.fqdn,
						Etag: to.Ptr("etag-123"),
						Properties: &privatedns.RecordSetProperties{
							TxtRecords: []*privatedns.TxtRecord{
								{
									Value: []*string{to.Ptr("validation-token-123")},
								},
							},
						},
					},
				},
			}
			prc := newFakeRecordSetsClient(recordSets)
			provider := &DNSProvider{
				recordClient:      prc,
				zoneClient:        pzc,
				resourceGroupName: "test-rg",
				zoneName:          "internal.example.com",
				log:               logrtesting.NewTestLogger(t),
			}

			assert.Equal(t, len(recordSets[tt.fqdn].GetTXTRecords()), 1)
			err := provider.CleanUp(t.Context(), tt.domain, tt.fqdn, tt.value)
			assert.NoError(t, err)
			assert.Equal(t, len(recordSets), 0)
		})
	}
}
