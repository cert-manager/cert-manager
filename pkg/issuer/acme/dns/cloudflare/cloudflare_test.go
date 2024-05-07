// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	cflareLiveTest bool
	cflareEmail    string
	cflareAPIKey   string
	cflareAPIToken string
	cflareDomain   string
)

type DNSProviderMock struct {
	mock.Mock
}

func (c *DNSProviderMock) makeRequest(ctx context.Context, method, uri string, body io.Reader) (json.RawMessage, error) {
	// stub makeRequest
	args := c.Called(method, uri, nil)
	return args.Get(0).([]uint8), args.Error(1)
}

func init() {
	cflareEmail = os.Getenv("CLOUDFLARE_EMAIL")
	cflareAPIKey = os.Getenv("CLOUDFLARE_API_KEY")
	cflareAPIToken = os.Getenv("CLOUDFLARE_API_TOKEN")
	cflareDomain = os.Getenv("CLOUDFLARE_DOMAIN")
	if len(cflareEmail) > 0 && (len(cflareAPIKey) > 0 || len(cflareAPIToken) > 0) && len(cflareDomain) > 0 {
		cflareLiveTest = true
	}
}

func TestNewDNSProviderValidAPIKey(t *testing.T) {
	t.Setenv("CLOUDFLARE_EMAIL", "")
	t.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProviderCredentials("123", "123", "", util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderValidAPIToken(t *testing.T) {
	t.Setenv("CLOUDFLARE_EMAIL", "")
	t.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProviderCredentials("123", "", "123", util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderKeyAndTokenProvided(t *testing.T) {
	t.Setenv("CLOUDFLARE_EMAIL", "")
	t.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProviderCredentials("123", "123", "123", util.RecursiveNameservers, "cert-manager-test")
	assert.EqualError(t, err, "the Cloudflare API key and API token cannot be both present simultaneously")
}

func TestNewDNSProviderValidApiKeyEnv(t *testing.T) {
	t.Setenv("CLOUDFLARE_EMAIL", "test@example.com")
	t.Setenv("CLOUDFLARE_API_KEY", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	t.Setenv("CLOUDFLARE_EMAIL", "")
	t.Setenv("CLOUDFLARE_API_KEY", "")
	_, err := NewDNSProvider(util.RecursiveNameservers, "cert-manager-test")
	assert.EqualError(t, err, "no Cloudflare credential has been given (can be either an API key or an API token)")
}

func TestFindNearestZoneForFQDN(t *testing.T) {
	dnsProvider := new(DNSProviderMock)

	noResult := []byte(`[]`)

	dnsProvider.On("makeRequest", "GET", "/zones?name=_acme-challenge.test.sub.domain.com", mock.Anything).Maybe().Return(noResult, nil)
	dnsProvider.On("makeRequest", "GET", "/zones?name=test.sub.domain.com", mock.Anything).Maybe().Return(noResult, nil)
	dnsProvider.On("makeRequest", "GET", "/zones?name=sub.domain.com", mock.Anything).Return([]byte(`[
		{"id":"1a23cc4567b8def91a01c23a456e78cd","name":"sub.domain.com"}
	]`), nil)

	zone, err := FindNearestZoneForFQDN(context.TODO(), dnsProvider, "_acme-challenge.test.sub.domain.com.")

	assert.NoError(t, err)
	assert.Equal(t, zone, DNSZone{ID: "1a23cc4567b8def91a01c23a456e78cd", Name: "sub.domain.com"})
}

func TestFindNearestZoneForFQDNInvalidToken(t *testing.T) {
	dnsProvider := new(DNSProviderMock)

	noResult := []byte(`[]`)

	dnsProvider.On("makeRequest", "GET", "/zones?name=_acme-challenge.test.sub.domain.com", mock.Anything).Maybe().Return(noResult, nil)
	dnsProvider.On("makeRequest", "GET", "/zones?name=test.sub.domain.com", mock.Anything).Maybe().Return(noResult, nil)
	dnsProvider.On("makeRequest", "GET", "/zones?name=sub.domain.com", mock.Anything).Maybe().Return(noResult, nil)
	dnsProvider.On("makeRequest", "GET", "/zones?name=domain.com", mock.Anything).Return(noResult,
		fmt.Errorf(`while attempting to find Zones for domain _acme-challenge.test.sub.domain.com
while querying the Cloudflare API for GET "/zones?name=_acme-challenge.test.sub.domain.com"
	 Error: 9109: Invalid access token`))

	_, err := FindNearestZoneForFQDN(context.TODO(), dnsProvider, "_acme-challenge.test.sub.domain.com.")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid access token")
}

func TestCloudFlarePresent(t *testing.T) {
	if !cflareLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(cflareEmail, cflareAPIKey, cflareAPIToken, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)

	err = provider.Present(context.TODO(), cflareDomain, "_acme-challenge."+cflareDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestCloudFlareCleanUp(t *testing.T) {
	if !cflareLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(cflareEmail, cflareAPIKey, cflareAPIToken, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)

	err = provider.CleanUp(context.TODO(), cflareDomain, "_acme-challenge."+cflareDomain+".", "123d==")
	assert.NoError(t, err)
}
