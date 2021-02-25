// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package cloudflare

import (
	"os"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	cflareLiveTest bool
	cflareEmail    string
	cflareAPIKey   string
	cflareAPIToken string
	cflareDomain   string
)

func init() {
	cflareEmail = os.Getenv("CLOUDFLARE_EMAIL")
	cflareAPIKey = os.Getenv("CLOUDFLARE_API_KEY")
	cflareDomain = os.Getenv("CLOUDFLARE_DOMAIN")
	if len(cflareEmail) > 0 && len(cflareAPIKey) > 0 && len(cflareDomain) > 0 {
		cflareLiveTest = true
	}
}

func restoreCloudFlareEnv() {
	os.Setenv("CLOUDFLARE_EMAIL", cflareEmail)
	os.Setenv("CLOUDFLARE_API_KEY", cflareAPIKey)
}

func TestNewDNSProviderValidAPIKey(t *testing.T) {
	os.Setenv("CLOUDFLARE_EMAIL", "")
	os.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProviderCredentials("123", "123", "", util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreCloudFlareEnv()
}

func TestNewDNSProviderValidAPIToken(t *testing.T) {
	os.Setenv("CLOUDFLARE_EMAIL", "")
	os.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProviderCredentials("123", "", "123", util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreCloudFlareEnv()
}

func TestNewDNSProviderKeyAndTokenProvided(t *testing.T) {
	os.Setenv("CLOUDFLARE_EMAIL", "")
	os.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProviderCredentials("123", "123", "123", util.RecursiveNameservers)
	assert.EqualError(t, err, "CloudFlare key and token are both present")
	restoreCloudFlareEnv()
}

func TestNewDNSProviderValidApiKeyEnv(t *testing.T) {
	os.Setenv("CLOUDFLARE_EMAIL", "test@example.com")
	os.Setenv("CLOUDFLARE_API_KEY", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreCloudFlareEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("CLOUDFLARE_EMAIL", "")
	os.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.EqualError(t, err, "CloudFlare credentials missing")
	restoreCloudFlareEnv()
}

func TestCloudFlarePresent(t *testing.T) {
	if !cflareLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(cflareEmail, cflareAPIKey, cflareAPIToken, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(cflareDomain, "_acme-challenge."+cflareDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestCloudFlareCleanUp(t *testing.T) {
	if !cflareLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(cflareEmail, cflareAPIKey, cflareAPIToken, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(cflareDomain, "_acme-challenge."+cflareDomain+".", "123d==")
	assert.NoError(t, err)
}
