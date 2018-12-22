package alibabadns

import (
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var (
	alibabaLiveTest        bool
	alibabaAccessKeyID     string
	alibabaAccessKeySecret string
	alibabaDomain          string
)

func init() {
	alibabaAccessKeyID = os.Getenv("ALIBABA_ACCESS_KEY_ID")
	alibabaAccessKeySecret = os.Getenv("ALIBABA_ACCESS_KEY_SECRET")
	alibabaDomain = os.Getenv("ALIBABA_DOMAIN")
	if len(alibabaAccessKeyID) > 0 && len(alibabaAccessKeySecret) > 0 && len(alibabaDomain) > 0 {
		alibabaLiveTest = true
	}
}

func TestLiveAlibabaDnsPresent(t *testing.T) {
	if !alibabaLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials(alibabaAccessKeyID, alibabaAccessKeySecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(alibabaDomain, "_acme-challenge", "123d==")
	assert.NoError(t, err)
}

//
func TestLiveAlibabaDnsCleanUp(t *testing.T) {
	if !alibabaLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials(alibabaAccessKeyID, alibabaAccessKeySecret, util.RecursiveNameservers)
	assert.NoError(t, err)
	err = provider.CleanUp(alibabaDomain, "_acme-challenge", "123d==")
	assert.NoError(t, err)
}
