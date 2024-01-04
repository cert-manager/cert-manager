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
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
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

	err = provider.Present(azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveAzureDnsCleanUp(t *testing.T) {
	if !azureLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 5)

	provider, err := NewDNSProviderCredentials("", azureClientID, azureClientSecret, azuresubscriptionID, azureTenantID, azureResourceGroupName, azureHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.CleanUp(azureDomain, "_acme-challenge."+azureDomain+".", "123d==")
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
		t.Setenv("AZURE_TENANT_ID", "fakeTenantID")
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
}
