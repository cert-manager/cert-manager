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

func TestLiveAzureDnsPresent(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.Present(context.TODO(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveAzureDnsPresentMultiple(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.Present(context.TODO(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
	err = provider.Present(context.TODO(), azureDomain, "_acme-challenge."+azureDomain+".", "1123d==")
	assert.NoError(t, err)
}

func TestLiveAzureDnsCleanUp(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 5)

	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.CleanUp(context.TODO(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveAzureDnsCleanUpMultiple(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 10)

	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.CleanUp(context.TODO(), azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
	err = provider.CleanUp(context.TODO(), azureDomain, "_acme-challenge."+azureDomain+".", "1123d==")
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

	err = provider.Present(context.TODO(), "example.com", "_acme-challenge.example.com.", "123d==")
	assert.Error(t, err)

	err = provider.CleanUp(context.TODO(), "example.com", "_acme-challenge.example.com.", "123d==")
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
	f, err := os.CreateTemp("", "")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	defer os.Remove(f.Name())

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
			if strings.HasSuffix(r.RequestURI, "/.well-known/openid-configuration") {
				tenantURL := strings.TrimSuffix("https://"+r.Host+r.RequestURI, "/.well-known/openid-configuration")

				w.Header().Set("Content-Type", "application/json")
				openidConfiguration := map[string]string{
					"token_endpoint":         tenantURL + "/oauth2/token",
					"authorization_endpoint": tenantURL + "/oauth2/authorize",
					"issuer":                 "https://fakeIssuer.com",
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
			accessToken := map[string]string{
				"access_token": tokens[receivedFederatedToken],
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
			token, err := spt.GetToken(context.TODO(), policy.TokenRequestOptions{Scopes: []string{"test"}})
			assert.NoError(t, err)
			assert.Equal(t, accessToken, token.Token, "Access token should have been set to a value returned by the webserver")

			// Overwrite the expires field to force the token to be re-read.
			newExpires := time.Now().Add(-1 * time.Second)
			v := reflect.ValueOf(spt.(*azidentity.WorkloadIdentityCredential)).Elem()
			expiresField := v.FieldByName("expires")
			reflect.NewAt(expiresField.Type(), expiresField.Addr().UnsafePointer()).
				Elem().Set(reflect.ValueOf(newExpires))
		}
	})

	t.Run("clientID overrides through managedIdentity section", func(t *testing.T) {
		managedIdentity := &v1.AzureManagedIdentity{ClientID: "anotherClientID"}

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.RequestURI, "/.well-known/openid-configuration") {
				tenantURL := strings.TrimSuffix("https://"+r.Host+r.RequestURI, "/.well-known/openid-configuration")

				w.Header().Set("Content-Type", "application/json")
				openidConfiguration := map[string]string{
					"token_endpoint":         tenantURL + "/oauth2/token",
					"authorization_endpoint": tenantURL + "/oauth2/authorize",
					"issuer":                 "https://fakeIssuer.com",
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
			accessToken := map[string]string{
				"access_token": "abc",
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

		token, err := spt.GetToken(context.TODO(), policy.TokenRequestOptions{Scopes: []string{"test"}})
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
			if strings.HasSuffix(r.RequestURI, "/.well-known/openid-configuration") {
				tenantURL := strings.TrimSuffix("https://"+r.Host+r.RequestURI, "/.well-known/openid-configuration")

				w.Header().Set("Content-Type", "application/json")
				openidConfiguration := map[string]string{
					"token_endpoint":         tenantURL + "/oauth2/token",
					"authorization_endpoint": tenantURL + "/oauth2/authorize",
					"issuer":                 "https://fakeIssuer.com",
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

		_, err = spt.GetToken(context.TODO(), policy.TokenRequestOptions{Scopes: []string{"test"}})
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

	err = dnsProvider.Present(context.TODO(), "test.com", "fqdn.test.com.", "test123")
	require.Error(t, err)
	require.ErrorContains(t, err, fmt.Sprintf(`Zone test.com. not found in AzureDNS for domain fqdn.test.com.. Err: request error:
GET %s/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network/dnsZones/test.com
--------------------------------------------------------------------------------
RESPONSE 502 Bad Gateway
ERROR CODE: TEST_ERROR_CODE
--------------------------------------------------------------------------------
see logs for more information`, ts.URL))
}
