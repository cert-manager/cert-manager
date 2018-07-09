package dnsmadeeasy

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testLive      bool
	testBaseURL   string
	testAPIKey    string
	testSecretKey string
	testDomain    string
)

func init() {
  testBaseURL = "https://api.sandbox.dnsmadeeasy.com/V2.0/"
	testAPIKey = os.Getenv("DNSMADEEASY_API_KEY")
	testSecretKey = os.Getenv("DNSMADEEASY_SECRET_KEY")
	testDomain = os.Getenv("DNSMADEEASY_DOMAIN")
	testLive = len(testAPIKey) > 0 && len(testSecretKey) > 0 && len(testDomain) > 0
}

func TestPresentAndCleanup(t *testing.T) {
	if !testLive {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProvider(testBaseURL, testAPIKey, testSecretKey)
	assert.NoError(t, err)

	err = provider.Present(testDomain, "", "123d==")
	assert.NoError(t, err)

	err = provider.CleanUp(testDomain, "", "123d==")
	assert.NoError(t, err)
}
