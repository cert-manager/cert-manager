/*
Copyright 2020 The cert-manager Authors.

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
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	acmednsLiveTest    bool
	acmednsHost        string
	acmednsAccountJSON []byte
	acmednsDomain      string
)

func init() {
	acmednsHost = os.Getenv("ACME_DNS_HOST")
	acmednsAccountJSON = []byte(os.Getenv("ACME_DNS_ACCOUNTS_JSON"))
	acmednsDomain = os.Getenv("ACME_DNS_DOMAIN")
	if len(acmednsHost) > 0 && len(acmednsAccountJSON) > 0 {
		acmednsLiveTest = true
	}
}

func TestValidJsonAccount(t *testing.T) {
	accountJSON := []byte(`{
        "domain": {
            "fulldomain": "fooldom",
            "password": "secret",
            "subdomain": "subdoom",
            "username": "usernom"
        }
    }`)
	provider, err := NewDNSProviderHostBytes("http://localhost/", accountJSON, util.RecursiveNameservers)
	assert.NoError(t, err, "Expected no error constructing DNSProvider")
	assert.Equal(t, provider.accounts["domain"].FullDomain, "fooldom")
}

func TestNoValidJsonAccount(t *testing.T) {
	accountJson := []byte(`{"duck": "quack"}`)
	_, err := NewDNSProviderHostBytes("http://localhost/", accountJson, util.RecursiveNameservers)
	assert.Error(t, err, "Expected error constructing DNSProvider from invalid accountJson")
}

func TestNoValidJson(t *testing.T) {
	accountJson := []byte("b00m")
	_, err := NewDNSProviderHostBytes("http://localhost/", accountJson, util.RecursiveNameservers)
	assert.Error(t, err, "Expected error constructing DNSProvider from invalid JSON")
}

func TestLiveAcmeDnsPresent(t *testing.T) {
	if !acmednsLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProviderHostBytes(acmednsHost, acmednsAccountJSON, util.RecursiveNameservers)
	assert.NoError(t, err)

	// ACME-DNS requires 43 character keys or it throws a bad TXT error
	err = provider.Present(context.TODO(), acmednsDomain, "", "LG3tptA6W7T1vw4ujbmDxH2lLu6r8TUIqLZD3pzPmgE")
	assert.NoError(t, err)
}
