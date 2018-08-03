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
	acmednsHost = os.Getenv("")
	acmednsAccountsJson = []byte(os.Getenv("AZURE_CLIENT_SECRET"))
	if len(acmednsHost) > 0 && len(acmednsAccountsJson) > 0 {
		acmednsLiveTest = true
	}
}

func TestLiveAzureDnsPresent(t *testing.T) {
	if !acmednsLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderHostBytes(acmednsHost, acmednsAccountsJson)
	assert.NoError(t, err)

	err = provider.Present(acmednsDomain, "", "123d==")
	assert.NoError(t, err)
}
