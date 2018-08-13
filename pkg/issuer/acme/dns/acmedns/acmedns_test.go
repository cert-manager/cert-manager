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

package acmedns

import (
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var (
	acmednsLiveTest    bool
	acmednsHost        string
	acmednsAccountJson []byte
	acmednsDomain      string
)

func init() {
	acmednsHost = os.Getenv("ACME_DNS_HOST")
	acmednsAccountJson = []byte(os.Getenv("ACME_DNS_ACCOUNTS_JSON"))
	acmednsDomain = os.Getenv("ACME_DNS_DOMAIN")
	if len(acmednsHost) > 0 && len(acmednsAccountJson) > 0 {
		acmednsLiveTest = true
	}
}

func TestLiveAcmeDnsPresent(t *testing.T) {
	if !acmednsLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderHostBytes(acmednsHost, acmednsAccountJson, util.RecursiveNameservers)
	assert.NoError(t, err)

	// ACME-DNS requires 43 character keys or it throws a bad TXT error
	err = provider.Present(acmednsDomain, "", "LG3tptA6W7T1vw4ujbmDxH2lLu6r8TUIqLZD3pzPmgE")
	assert.NoError(t, err)
}
