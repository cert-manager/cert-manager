// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package azuredns

import (
	"os"
	"testing"
	"time"

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
	validEnv := []string{"", "AzurePublicCloud", "AzureChinaCloud", "AzureGermanCloud", "AzureUSGovernmentCloud"}
	for _, env := range validEnv {
		_, err := NewDNSProviderCredentials(env, "cid", "secret", "", "", "", "", util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
		assert.NoError(t, err)
	}

	_, err := NewDNSProviderCredentials("invalid env", "cid", "secret", "", "", "", "", util.RecursiveNameservers, false, &v1.AzureManagedIdentity{})
	assert.Error(t, err)
}
