// +skip_license_check

package infobloxdns

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	triggerTest bool

	gridHost     string
	wapiUsername string
	wapiPassword string
	wapiPort     string
	wapiVersion  string
	sslVerify    bool

	domain string
)

func init() {
	gridHost = os.Getenv("INFOBLOX_HOST")
	wapiUsername = os.Getenv("INFOBLOX_WAPI_USERNAME")
	wapiPassword = os.Getenv("INFOBLOX_WAPI_PASSWORD")
	wapiVersion = os.Getenv("INFOBLOX_WAPI_VERSION")

	if len(os.Getenv("INFOBLOX_WAPI_PORT")) > 0 {
		wapiPort = os.Getenv("INFOBLOX_WAPI_PORT")
	} else {
		wapiPort = "80"
	}

	if len(os.Getenv("INFOBLOX_SSL_VERIFY")) > 0 {
		sslVerify = true
	} else {
		sslVerify = false
	}

	if len(gridHost) > 0 && len(wapiUsername) > 0 && len(wapiPassword) > 0 && len(wapiVersion) > 0 {
		triggerTest = true
	}

	domain = os.Getenv("INFOBLOX_DOMAIN")
}

func TestInfobloxPresent(t *testing.T) {
	if !triggerTest {
		t.Skip("skipping test")
	}

	provider, err := NewDNSProvider(gridHost, wapiUsername, wapiPassword, wapiPort, wapiVersion, sslVerify, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(domain, "", "123d==")
	assert.NoError(t, err)
}

func TestInfobloxCleanUp(t *testing.T) {
	if !triggerTest {
		t.Skip("skipping test")
	}

	time.Sleep(time.Second * 10)
	provider, err := NewDNSProvider(gridHost, wapiUsername, wapiPassword, wapiPort, wapiVersion, sslVerify, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(domain, "", "123d==")
	assert.NoError(t, err)
}
