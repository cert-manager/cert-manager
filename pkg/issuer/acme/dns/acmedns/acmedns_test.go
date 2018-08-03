package acmedns

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var (
	acmednsLiveTest     bool
	acmednsHost         string
	acmednsAccountsJson []byte
	acmednsDomain       string
)

func init() {
	acmednsHost = os.Getenv("ACME_DNS_HOST")
	acmednsAccountsJson = []byte(os.Getenv("ACME_DNS_ACCOUNTS_JSON"))
	acmednsDomain = os.Getenv("ACME_DNS_DOMAIN")
	if len(acmednsHost) > 0 && len(acmednsAccountsJson) > 0 {
		acmednsLiveTest = true
	}
}

func TestLiveAcmeDnsPresent(t *testing.T) {
	if !acmednsLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderHostBytes(acmednsHost, acmednsAccountsJson)
	assert.NoError(t, err)

	// ACME-DNS requires 43 character keys or it throws a bad TXT error
	err = provider.Present(acmednsDomain, "", "LG3tptA6W7T1vw4ujbmDxH2lLu6r8TUIqLZD3pzPmgE")
	assert.NoError(t, err)
}
