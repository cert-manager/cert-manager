// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/
package alidns

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

func TestLiveAlidnsPresent(t *testing.T) {
	if !alibabaLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials(alibabaAccessKeyID, alibabaAccessKeySecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(alibabaDomain, "_acme-challenge", "123d==")
	assert.NoError(t, err)
}

//
func TestLiveAlidnsCleanUp(t *testing.T) {
	if !alibabaLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderCredentials(alibabaAccessKeyID, alibabaAccessKeySecret, util.RecursiveNameservers)
	assert.NoError(t, err)
	err = provider.CleanUp(alibabaDomain, "_acme-challenge", "123d==")
	assert.NoError(t, err)
}
