package digitalocean

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	doLiveTest bool
	doToken    string
	doDomain   string
)

func init() {
	doToken = os.Getenv("DIGITALOCEAN_TOKEN")
	doDomain = os.Getenv("DIGITALOCEAN_DOMAIN")
	if len(doToken) > 0 && len(doDomain) > 0 {
		doLiveTest = true
	}
}

func restoreEnv() {
	os.Setenv("DIGITALOCEAN_TOKEN", doToken)
}

func TestNewDNSProviderValid(t *testing.T) {
	os.Setenv("DIGITALOCEAN_TOKEN", "")
	_, err := NewDNSProviderCredentials("123")
	assert.NoError(t, err)
	restoreEnv()
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	os.Setenv("DIGITALOCEAN_TOKEN", "123")
	_, err := NewDNSProvider()
	assert.NoError(t, err)
	restoreEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("DIGITALOCEAN_TOKEN", "")
	_, err := NewDNSProvider()
	assert.EqualError(t, err, "DigitalOcean token missing")
	restoreEnv()
}

func TestDigitalOceanPresent(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(doToken)
	assert.NoError(t, err)

	err = provider.Present(doDomain, "", "123d==")
	assert.NoError(t, err)
}

func TestDigitalOceanCleanUp(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(doToken)
	assert.NoError(t, err)

	err = provider.CleanUp(doDomain, "", "123d==")
	assert.NoError(t, err)
}
