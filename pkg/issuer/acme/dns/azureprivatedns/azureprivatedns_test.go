// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package azureprivatedns

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
	privatedns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/rand"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	azurePrivateLiveTest          bool
	azurePrivateClientID          string
	azurePrivateClientSecret      string
	azurePrivatesubscriptionID    string
	azurePrivateTenantID          string
	azurePrivateResourceGroupName string
	azurePrivateHostedZoneName    string
	azurePrivateDomain            string
)

func init() {
	azurePrivateClientID = os.Getenv("AZURE_CLIENT_ID")
	azurePrivateClientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	azurePrivatesubscriptionID = os.Getenv("AZURE_SUBSCRIPTION_ID")
	azurePrivateTenantID = os.Getenv("AZURE_TENANT_ID")
	azurePrivateResourceGroupName = os.Getenv("AZURE_RESOURCE_GROUP")
	azurePrivateHostedZoneName = os.Getenv("AZURE_ZONE_NAME")
	azurePrivateDomain = os.Getenv("AZURE_DOMAIN")
	if len(azurePrivateClientID) > 0 && len(azurePrivateClientSecret) > 0 && len(azurePrivateDomain) > 0 {
		azurePrivateLiveTest = true
	}
}

func TestLiveAzurePrivateDnsPresent(t *testing.T) {
	if !azurePrivateLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials("", azurePrivateClientID, azurePrivateClientSecret, azurePrivatesubscriptionID, azurePrivateTenantID, azurePrivateResourceGroupName, azurePrivateHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.Present(context.TODO(), azurePrivateDomain, "_acme-challenge."+azurePrivateDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveAzurePrivateDnsPresentMultiple(t *testing.T) {
	if !azurePrivateLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials("", azurePrivateClientID, azurePrivateClientSecret, azurePrivatesubscriptionID, azurePrivateTenantID, azurePrivateResourceGroupName, azurePrivateHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.Present(context.TODO(), azurePrivateDomain, "_acme-challenge."+azurePrivateDomain+".", "123d==")
	assert.NoError(t, err)
	err = provider.Present(context.TODO(), azurePrivateDomain, "_acme-challenge."+azurePrivateDomain+".", "1123d==")
	assert.NoError(t, err)
}

func TestLiveAzurePrivateDnsCleanUp(t *testing.T) {
	if !azurePrivateLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 5)

	provider, err := NewDNSProviderCredentials("", azurePrivateClientID, azurePrivateClientSecret, azurePrivatesubscriptionID, azurePrivateTenantID, azurePrivateResourceGroupName, azurePrivateHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.CleanUp(context.TODO(), azurePrivateDomain, "_acme-challenge."+azurePrivateDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestLiveAzurePrivateDnsCleanUpMultiple(t *testing.T) {
	if !azurePrivateLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 10)

	provider, err := NewDNSProviderCredentials("", azurePrivateClientID, azurePrivateClientSecret, azurePrivatesubscriptionID, azurePrivateTenantID, azurePrivateResourceGroupName, azurePrivateHostedZoneName, util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.NoError(t, err)

	err = provider.CleanUp(context.TODO(), azurePrivateDomain, "_acme-challenge."+azurePrivateDomain+".", "123d==")
	assert.NoError(t, err)
	err = provider.CleanUp(context.TODO(), azurePrivateDomain, "_acme-challenge."+azurePrivateDomain+".", "1123d==")
	assert.NoError(t, err)
}

func TestInvalidAzurePrivateDns(t *testing.T) {
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
	f, err := os.CreateTemp("", "")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	defer os.Remove(f.Name())

	if err := f.Close(); err != nil {
		assert.FailNow(t, err.Error())
	}

	populateFederatedToken(t, f.Name(), "random-jwt")

	if os.Getenv("AZURE_TENANT_ID") == "" {
		t.Setenv("AZURE_TENANT_ID", "adfs")
	}

	if os.Getenv("AZURE_CLIENT_ID") == "" {
		t.Setenv("AZURE_CLIENT_ID", "fakeClientID")
	}

	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", f.Name())

	t.Run("token refresh", func(t *testing.T) {
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
		assert.ErrorContains(t, err, fmt.Sprintf(`authentication failed:\nPOST %s/adfs/oauth2/token\n--------------------------------------------------------------------------------\nRESPONSE 502 Bad Gateway\n--------------------------------------------------------------------------------\nsee logs for more information`, ts.URL))
	})
}

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

	zc, err := privatedns.NewPrivateZonesClient("subscriptionID", nil, &arm.ClientOptions{ClientOptions: clientOpt})
	require.NoError(t, err)

	dnsProvider := DNSProvider{
		dns01Nameservers:  util.RecursiveNameservers,
		resourceGroupName: "resourceGroupName",
		zoneClient:        zc,
	}

	err = dnsProvider.Present(context.TODO(), "test.com", "fqdn.test.com.", "test123")
	require.Error(t, err)
	require.ErrorContains(t, err, fmt.Sprintf(`Zone test.com. not found in Azure Private DNS for domain fqdn.test.com.. Err: request error:\nGET %s/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network/privateDnsZones/test.com\n--------------------------------------------------------------------------------\nRESPONSE 502 Bad Gateway\nERROR CODE: TEST_ERROR_CODE\n--------------------------------------------------------------------------------\nsee logs for more information`, ts.URL))
}
