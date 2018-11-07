// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package dnspod

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	dnspodLiveTest bool
	dnspodAPIKey   string
	dnspodDomain   string
)

func init() {
	dnspodAPIKey = os.Getenv("DNSPOD_API_KEY")
	dnspodDomain = os.Getenv("DNSPOD_DOMAIN")
	if len(dnspodAPIKey) > 0 && len(dnspodDomain) > 0 {
		dnspodLiveTest = true
	}
}

func restorednspodEnv() {
	os.Setenv("DNSPOD_API_KEY", dnspodAPIKey)
}

func TestNewDNSProviderValid(t *testing.T) {
	os.Setenv("DNSPOD_API_KEY", "")
	_, err := NewDNSProviderCredentials("123")
	assert.NoError(t, err)
	restorednspodEnv()
}
func TestNewDNSProviderValidEnv(t *testing.T) {
	os.Setenv("DNSPOD_API_KEY", "123")
	_, err := NewDNSProvider()
	assert.NoError(t, err)
	restorednspodEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("DNSPOD_API_KEY", "")
	_, err := NewDNSProvider()
	assert.EqualError(t, err, "dnspod credentials missing")
	restorednspodEnv()
}

func TestLivednspodPresent(t *testing.T) {
	if !dnspodLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(dnspodAPIKey)
	assert.NoError(t, err)

	err = provider.Present(dnspodDomain, "", "123d==")
	assert.NoError(t, err)
}

func TestLivednspodCleanUp(t *testing.T) {
	if !dnspodLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 1)

	provider, err := NewDNSProviderCredentials(dnspodAPIKey)
	assert.NoError(t, err)

	err = provider.CleanUp(dnspodDomain, "", "123d==")
	assert.NoError(t, err)
}
