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

package dnsimple

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	dnsimpleLiveTest   bool
	dnsimpleOauthToken string
	dnsimpleDomain     string
)

func init() {
	dnsimpleOauthToken = getOauthToken()
	dnsimpleDomain = os.Getenv("DNSIMPLE_DOMAIN")

	if dnsimpleOauthToken != "" && dnsimpleDomain != "" {
		dnsimpleLiveTest = true
	}
}

func TestLiveDNSimpleDnsPresent(t *testing.T) {
	if !dnsimpleLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(dnsimpleOauthToken, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(dnsimpleDomain, "", "123d==")
	assert.NoError(t, err)
}

func TestLiveDNSimpleDnsPresentIdempotent(t *testing.T) {
	TestLiveDNSimpleDnsPresent(t)
}

func TestLiveDNSimpleDnsCleanUp(t *testing.T) {
	if !dnsimpleLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 5)

	provider, err := NewDNSProviderCredentials(dnsimpleOauthToken, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(dnsimpleDomain, "", "123d==")
	assert.NoError(t, err)
}

func TestLiveDNSimpleDnsCleanUpIdempotent(t *testing.T) {
	TestLiveDNSimpleDnsCleanUp(t)
}
