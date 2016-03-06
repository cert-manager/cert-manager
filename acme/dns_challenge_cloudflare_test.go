package acme

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	cflareLiveTest bool
	cflareEmail    string
	cflareAPIKey   string
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

func TestNewDNSProviderCloudFlareValid(t *testing.T) {
	os.Setenv("CLOUDFLARE_EMAIL", "")
	os.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProviderCloudFlare("123", "123")
	assert.NoError(t, err)
	restoreCloudFlareEnv()
}

func TestNewDNSProviderCloudFlareValidEnv(t *testing.T) {
	os.Setenv("CLOUDFLARE_EMAIL", "test@example.com")
	os.Setenv("CLOUDFLARE_API_KEY", "123")
	_, err := NewDNSProviderCloudFlare("", "")
	assert.NoError(t, err)
	restoreCloudFlareEnv()
}

func TestNewDNSProviderCloudFlareMissingCredErr(t *testing.T) {
	os.Setenv("CLOUDFLARE_EMAIL", "")
	os.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProviderCloudFlare("", "")
	assert.EqualError(t, err, "CloudFlare credentials missing")
	restoreCloudFlareEnv()
}

func TestCloudFlarePresent(t *testing.T) {
	if !cflareLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCloudFlare(cflareEmail, cflareAPIKey)
	assert.NoError(t, err)

	err = provider.Present(cflareDomain, "", "123d==")
	assert.NoError(t, err)
}

func TestCloudFlareCleanUp(t *testing.T) {
	if !cflareLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCloudFlare(cflareEmail, cflareAPIKey)
	assert.NoError(t, err)

	err = provider.CleanUp(cflareDomain, "", "123d==")
	assert.NoError(t, err)
}
