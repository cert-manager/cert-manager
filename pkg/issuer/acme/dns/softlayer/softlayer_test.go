/*
Copyright 2018 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package softlayer

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	softlayerLiveTest bool
	softlayerUsername string
	softlayerAPIKey   string
	softlayerDomain   string
)

func init() {
	softlayerUsername = os.Getenv("SL_USERNAME")
	softlayerAPIKey = os.Getenv("SL_API_KEY")
	softlayerDomain = os.Getenv("SL_DOMAIN")
	if len(softlayerUsername) > 0 && len(softlayerAPIKey) > 0 && len(softlayerDomain) > 0 {
		softlayerLiveTest = true
	}
}

func restoreSoftlayerEnv() {
	os.Setenv("SL_USERNAME", softlayerUsername)
	os.Setenv("SL_API_KEY", softlayerAPIKey)
}

func TestNewDNSProviderValid(t *testing.T) {
	os.Setenv("SL_USERNAME", "")
	os.Setenv("SL_API_KEY", "")
	_, err := NewDNSProviderCredentials("123", "123", util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreSoftlayerEnv()
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	os.Setenv("SL_USERNAME", "test@example.com")
	os.Setenv("SL_API_KEY", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreSoftlayerEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("SL_USERNAME", "")
	os.Setenv("SL_API_KEY", "")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.EqualError(t, err, "Softlayer credentials missing")
	restoreSoftlayerEnv()
}

func TestSoftlayerPresent(t *testing.T) {
	if !softlayerLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(softlayerUsername, softlayerAPIKey, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(softlayerDomain, "_acme-challenge."+softlayerDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestSoftlayerCleanUp(t *testing.T) {
	if !softlayerLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(softlayerUsername, softlayerAPIKey, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(softlayerDomain, "_acme-challenge."+softlayerDomain+".", "123d==")
	assert.NoError(t, err)
}
