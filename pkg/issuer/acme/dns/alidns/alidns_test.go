package alidns

import (
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var (
	gAliLiveTest    bool
	accessKeyId     string
	accessKeySecret string
	aliDomain       string
)

func init()  {
	accessKeyId = os.Getenv("ACCESS_KEY_ID")
	accessKeySecret = os.Getenv("ACCESS_KEY_SECRET")
	aliDomain = os.Getenv("ALI_DOMAIN")

	if len(accessKeyId)>0 && len(accessKeySecret)>0 && len(aliDomain)>0 {
		gAliLiveTest = true
	}
}

func determineWhetherToTest(t *testing.T) {
	if !gAliLiveTest {
		t.Skip("skipping live test")
	}
}

func TestDNSProviderPresent(t *testing.T) {
	determineWhetherToTest(t)

	provider, err := NewDNSProvider(defaultRegionID, accessKeyId, accessKeySecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(aliDomain, "_acme-challenge."+aliDomain+".", "acme-challenge_value")
	assert.NoError(t, err)
}

func TestDNSProviderCleanUp(t *testing.T) {
	determineWhetherToTest(t)

	provider, err := NewDNSProvider(defaultRegionID, accessKeyId, accessKeySecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(aliDomain, "_acme-challenge."+aliDomain+".", "acme-challenge_value")
	assert.NoError(t, err)
}
