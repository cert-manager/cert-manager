/*
Copyright 2019 The Jetstack cert-manager contributors.

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

func init() {
	accessKeyId = os.Getenv("ACCESS_KEY_ID")
	accessKeySecret = os.Getenv("ACCESS_KEY_SECRET")
	aliDomain = os.Getenv("ALI_DOMAIN")

	if len(accessKeyId) > 0 && len(accessKeySecret) > 0 && len(aliDomain) > 0 {
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
