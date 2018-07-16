package pdns

import (
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	pdnsLiveTest bool
	pdnsURL      *url.URL
	pdnsURLStr   string
	pdnsAPIKey   string
	pdnsDomain   string
)

func init() {
	pdnsURLStr = os.Getenv("PDNS_API_URL")
	pdnsURL, _ = url.Parse(pdnsURLStr)
	pdnsAPIKey = os.Getenv("PDNS_API_KEY")
	pdnsDomain = os.Getenv("PDNS_DOMAIN")
	if len(pdnsURLStr) > 0 && len(pdnsAPIKey) > 0 && len(pdnsDomain) > 0 {
		pdnsLiveTest = true
	}
}

func restoreEnv() {
	os.Setenv("PDNS_API_URL", pdnsURLStr)
	os.Setenv("PDNS_API_KEY", pdnsAPIKey)
}

func TestNewDNSProviderValid(t *testing.T) {
	defer restoreEnv()
	os.Setenv("PDNS_API_URL", "")
	os.Setenv("PDNS_API_KEY", "")

	tmpURL, _ := url.Parse("http://localhost:8081")
	_, err := NewDNSProviderCredentials(tmpURL, "123")
	assert.NoError(t, err)
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	defer restoreEnv()
	os.Setenv("PDNS_API_URL", "http://localhost:8081")
	os.Setenv("PDNS_API_KEY", "123")

	_, err := NewDNSProvider()
	assert.NoError(t, err)
}

func TestNewDNSProviderMissingHostErr(t *testing.T) {
	defer restoreEnv()
	os.Setenv("PDNS_API_URL", "")
	os.Setenv("PDNS_API_KEY", "123")

	_, err := NewDNSProvider()
	assert.EqualError(t, err, "PDNS: some credentials information are missing: PDNS_API_URL")
}

func TestNewDNSProviderMissingKeyErr(t *testing.T) {
	defer restoreEnv()
	os.Setenv("PDNS_API_URL", pdnsURLStr)
	os.Setenv("PDNS_API_KEY", "")

	_, err := NewDNSProvider()
	assert.EqualError(t, err, "PDNS: some credentials information are missing: PDNS_API_KEY,PDNS_API_URL")
}

func TestPdnsPresentAndCleanup(t *testing.T) {
	if !pdnsLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(pdnsURL, pdnsAPIKey)
	assert.NoError(t, err)

	err = provider.Present(pdnsDomain, "", "123d==")
	assert.NoError(t, err)

	err = provider.CleanUp(pdnsDomain, "", "123d==")
	assert.NoError(t, err)
}
