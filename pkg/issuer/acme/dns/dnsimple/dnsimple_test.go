package dnsimple

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	dnsimpleLiveTest   bool
	dnsimpleOauthToken string
	dnsimpleDomain     string
)

func init() {
	dnsimpleOauthToken = getOauthToken()
	dnsimpleDomain = os.Getenv("DNSIMPLE_DOMAIN")

	if dnsimpleOauthToken != "" && dnsimpleDomain != "" {
		dnsimpleLiveTest = true
	}
}

func TestLiveDNSimpleDnsPresent(t *testing.T) {
	if !dnsimpleLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(dnsimpleOauthToken)
	assert.NoError(t, err)

	err = provider.Present(dnsimpleDomain, "", "123d==")
	assert.NoError(t, err)
}

func TestLiveDNSimpleDnsPresentIdempotent(t *testing.T) {
	TestLiveDNSimpleDnsPresent(t)
}

func TestLiveDNSimpleDnsCleanUp(t *testing.T) {
	if !dnsimpleLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 5)

	provider, err := NewDNSProviderCredentials(dnsimpleOauthToken)
	assert.NoError(t, err)

	err = provider.CleanUp(dnsimpleDomain, "", "123d==")
	assert.NoError(t, err)
}

func TestLiveDNSimpleDnsCleanUpIdempotent(t *testing.T) {
	TestLiveDNSimpleDnsCleanUp(t)
}
