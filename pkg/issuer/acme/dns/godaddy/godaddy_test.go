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
package godaddy

import (
	"testing"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/require"
)

var (
	apiKey    string
	apiSecret string
	domain    string
)

var doLiveTest = false

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc      string
		apiKey    string
		apiSecret string
		expected  string
	}{
		{
			desc:      "success",
			apiKey:    "123",
			apiSecret: "456",
		},
		{
			desc:      "missing credentials",
			apiKey:    "",
			apiSecret: "",
			expected:  "godaddy: some credentials are missing: apiKey or apiSecret",
		},
		{
			desc:      "missing access key",
			apiKey:    "",
			apiSecret: "456",
			expected:  "godaddy: some credentials are missing: apiKey or apiSecret",
		},
		{
			desc:      "missing secret key",
			apiKey:    "123",
			apiSecret: "",
			expected:  "godaddy: some credentials are missing: apiKey or apiSecret",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {

			p, err := NewDNSProvider(test.apiKey, test.apiSecret, util.RecursiveNameservers)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestLivePresent(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	apiKey = "new-api-key"
	apiSecret = "new-api-secret"
	domain = "api.test.com"
	provider, err := NewDNSProvider(apiKey, apiSecret, util.RecursiveNameservers)

	require.NoError(t, err)

	err = provider.Present(domain, "", "123d==")
	require.NoError(t, err)
}

func TestLiveCleanUp(t *testing.T) {
	if !doLiveTest {
		t.Skip("Skipping live test")
	}
	apiKey = "new-api-key"
	apiSecret = "new-api-secret"
	domain = "api.test.com"
	provider, err := NewDNSProvider(apiKey, apiSecret, util.RecursiveNameservers)
	require.NoError(t, err)

	err = provider.CleanUp(domain, "", "123d==")
	require.NoError(t, err)
}
