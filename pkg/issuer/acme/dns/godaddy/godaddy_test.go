// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package godaddy implements a DNS provider for solving the DNS-01 challenge
// using Godaddy DNS.
package godaddy

import (
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var (
	doLiveTest    bool
	doDomain      string
	doApiKey      string
	doApiSecret   string
)

func init() {
	doApiKey = os.Getenv("GODADDY_API_KEY")
	doApiSecret = os.Getenv("GODADDY_API_SECRET")
	doDomain = "example.com"
	if len(doApiKey) > 0 && len(doApiSecret) > 0 {
		doLiveTest = true
	}
}

func restoreEnv() {
	os.Setenv("GODADDY_API_KEY", doApiKey)
	os.Setenv("GODADDY_API_SECRET", doApiSecret)
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	os.Setenv("GODADDY_API_KEY", "123")
	os.Setenv("GODADDY_API_SECRET", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("GODADDY_API_KEY", "")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.EqualError(t, err, "Godaddy: credentials missing (apiKey and/or apiSecret)")
	restoreEnv()
}

func TestGodaddyPresent(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestGodaddyCleanup(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}