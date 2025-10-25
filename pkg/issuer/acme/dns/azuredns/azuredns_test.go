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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	dns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	privatedns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/rand"

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

type fakePrivateZonesClient struct {
	zones map[string]privatedns.PrivateZone
}

func newFakePrivateZonesClient(zones map[string]privatedns.PrivateZone) *fakePrivateZonesClient {
	return &fakePrivateZonesClient{zones: zones}
}

func (fpz *fakePrivateZonesClient) Get(ctx context.Context, resourceGroupName string, privateZoneName string, options *privatedns.PrivateZonesClientGetOptions) (privatedns.PrivateZonesClientGetResponse, error) {
	z, ok := fpz.zones[privateZoneName]
	if !ok {
		return privatedns.PrivateZonesClientGetResponse{}, errors.New("no zone found")
	}

	return privatedns.PrivateZonesClientGetResponse{PrivateZone: z}, nil
}

type fakePrivateRecordsClient struct {
	records map[string]privatedns.RecordSet
}

func newFakeRecordSetsClient(records map[string]privatedns.RecordSet) *fakePrivateRecordsClient {
	return &fakePrivateRecordsClient{records: records}
}

func (fpr *fakePrivateRecordsClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, privateZoneName string, recordType privatedns.RecordType, relativeRecordSetName string, parameters privatedns.RecordSet, options *privatedns.RecordSetsClientCreateOrUpdateOptions) (privatedns.RecordSetsClientCreateOrUpdateResponse, error) {
	key := fmt.Sprintf("%s.%s", relativeRecordSetName, privateZoneName)
	fpr.records[key] = parameters
	return privatedns.RecordSetsClientCreateOrUpdateResponse{}, nil
}

func (fpr *fakePrivateRecordsClient) Get(ctx context.Context, resourceGroupName string, privateZoneName string, recordType privatedns.RecordType, relativeRecordSetName string, options *privatedns.RecordSetsClientGetOptions) (privatedns.RecordSetsClientGetResponse, error) {
	key := fmt.Sprintf("%s.%s", relativeRecordSetName, privateZoneName)
	r, ok := fpr.records[key]
	if !ok {
		return privatedns.RecordSetsClientGetResponse{}, errors.New("no record found")
	}

	return privatedns.RecordSetsClientGetResponse{RecordSet: r}, nil
}

func (fpr *fakePrivateRecordsClient) Delete(ctx context.Context, resourceGroupName string, privateZoneName string, recordType privatedns.RecordType, relativeRecordSetName string, options *privatedns.RecordSetsClientDeleteOptions) (privatedns.RecordSetsClientDeleteResponse, error) {
	delete(fpr.records, fmt.Sprintf("%s.%s", relativeRecordSetName, privateZoneName))
	return privatedns.RecordSetsClientDeleteResponse{}, nil
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

	// This test tests the stabilizeError function, it makes sure that authentication errors
	// are also made stable. We want our error messages to be the same when the cause
	// is the same to avoid spurious challenge updates.
	// Specifically, this test makes sure that the errors of type AuthenticationFailedError
	// are made stable. These errors are returned by the recordClient and zoneClient when
	// they fail to authenticate. We simulate this by calling the GetToken function and
	// returning a 502 Bad Gateway error.
	t.Run("errors should be made stable", func(t *testing.T) {
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

			w.WriteHeader(http.StatusBadGateway)
			randomMessage := "test error message: " + rand.String(10)
			payload := fmt.Sprintf(`{"error":{"code":"TEST_ERROR_CODE","message":"%s"}}`, randomMessage)
			if _, err := w.Write([]byte(payload)); err != nil {
				assert.FailNow(t, err.Error())
			}
		}))
		defer ts.Close()

		ambient := true
		clientOpt := policy.ClientOptions{
			Cloud:     cloud.Configuration{ActiveDirectoryAuthorityHost: ts.URL},
			Transport: ts.Client(),
		}

		spt, err := getAuthorization(clientOpt, "", "", "", ambient, managedIdentity)
		assert.NoError(t, err)

		_, err = spt.GetToken(t.Context(), policy.TokenRequestOptions{Scopes: []string{"test"}})
		err = stabilizeError(err)
		assert.Error(t, err)
		assert.ErrorContains(t, err, fmt.Sprintf(`authentication failed:
POST %s/adfs/oauth2/token
--------------------------------------------------------------------------------
RESPONSE 502 Bad Gateway
--------------------------------------------------------------------------------
see logs for more information`, ts.URL))
	})
}

// TestStabilizeResponseError tests that the ResponseError errors returned by the AzureDNS API are
// changed to be stable. We want our error messages to be the same when the cause
// is the same to avoid spurious challenge updates.
func TestStabilizeResponseError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		randomMessage := "test error message: " + rand.String(10)
		payload := fmt.Sprintf(`{"error":{"code":"TEST_ERROR_CODE","message":"%s"}}`, randomMessage)
		if _, err := w.Write([]byte(payload)); err != nil {
			assert.FailNow(t, err.Error())
		}
	}))

	defer ts.Close()

	clientOpt := policy.ClientOptions{
		Cloud: cloud.Configuration{
			ActiveDirectoryAuthorityHost: ts.URL,
			Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {
					Audience: ts.URL,
					Endpoint: ts.URL,
				},
			},
		},
		Transport: ts.Client(),
	}

	zc, err := dns.NewZonesClient("subscriptionID", nil, &arm.ClientOptions{ClientOptions: clientOpt})
	require.NoError(t, err)

	dnsProvider := DNSProvider{
		dns01Nameservers:  util.RecursiveNameservers,
		resourceGroupName: "resourceGroupName",
		zoneClient:        zc,
	}

	err = dnsProvider.Present(t.Context(), "test.com", "fqdn.test.com.", "test123")
	require.Error(t, err)
	require.ErrorContains(t, err, fmt.Sprintf(`Zone test.com. not found in AzureDNS for domain fqdn.test.com.. Err: request error:
GET %s/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network/dnsZones/test.com
--------------------------------------------------------------------------------
RESPONSE 502 Bad Gateway
ERROR CODE: TEST_ERROR_CODE
--------------------------------------------------------------------------------
see logs for more information`, ts.URL))
}

func TestLiveAzurePrivateDNSPresent(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, true, &v1.AzureManagedIdentity{}, WithPrivateZone(true))
	require.NoError(t, err)

	err = provider.Present(t.Context(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
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
			pzc := newFakePrivateZonesClient(map[string]privatedns.PrivateZone{
				tt.domain: {Name: &tt.domain},
			})
			prc := newFakeRecordSetsClient(map[string]privatedns.RecordSet{
				tt.fqdn: {
					Name: &tt.fqdn,
					Etag: new(string),
					Properties: &privatedns.RecordSetProperties{
						TxtRecords: make([]*privatedns.TxtRecord, 0),
					},
				},
			})
			provider := &DNSProvider{
				privateRecordClient: prc,
				privateZoneClient:   pzc,
				resourceGroupName:   "test-rg",
				zoneName:            "internal.example.com",
				isPrivateZone:       true,
				log:                 logrtesting.NewTestLogger(t),
			}

			err := provider.Present(t.Context(), tt.domain, tt.fqdn, tt.value)
			assert.NoError(t, err)
			val := *(prc.records[tt.fqdn].Properties.TxtRecords[0].Value[0])
			assert.Equal(t, tt.value, val)
		})
	}
}
