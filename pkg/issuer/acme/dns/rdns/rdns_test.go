package rdns

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	rdnsLiveTest  bool
	rdnsToken     string
	rdnsDomain    string
	clusterDomain string
)

func init() {
	rdnsToken = os.Getenv("RDNS_TOKEN")
	rdnsDomain = os.Getenv("RDNS_API_ENDPOINT")
	clusterDomain = os.Getenv("RDNS_CLUSTER_DOMAIN")
	if len(rdnsToken) > 0 && len(rdnsDomain) > 0 && len(clusterDomain) > 0 {
		rdnsLiveTest = true
	}
}

func TestNewDNSProviderValid(t *testing.T) {
	os.Setenv("RDNS_API_ENDPOINT", "abc.on-rio-io")
	os.Setenv("RDNS_TOKEN", "abc")

	_, err := NewDNSProvider()
	assert.NoError(t, err)
}

func TestNewDNSProviderTokenEmpty(t *testing.T) {
	os.Setenv("RDNS_API_ENDPOINT", "abc.on-rio-io")
	os.Setenv("RDNS_TOKEN", "")
	_, err := NewDNSProvider()

	assert.EqualError(t, err, "rdns token is missing")
}

func TestNewDNSProviderAPIEndpointEmpty(t *testing.T) {
	os.Setenv("RDNS_API_ENDPOINT", "")
	os.Setenv("RDNS_TOKEN", "abc")
	_, err := NewDNSProvider()

	assert.EqualError(t, err, "rdns api endpoint is empty")
}

func TestDNSProvider_Present(t *testing.T) {
	if !rdnsLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredential(rdnsDomain, rdnsToken)
	assert.NoError(t, err)

	err = provider.Present(clusterDomain, rdnsToken, "123d==")
	assert.NoError(t, err)
}

func TestDNSProvider_CleanUp(t *testing.T) {
	if !rdnsLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredential(rdnsDomain, rdnsToken)
	assert.NoError(t, err)

	err = provider.CleanUp(clusterDomain, rdnsToken, "123d==")
	assert.NoError(t, err)
}
