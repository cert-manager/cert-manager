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

package digitalocean

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	doLiveTest bool
	doToken    string
	doDomain   string
)

func init() {
	doToken = os.Getenv("DIGITALOCEAN_TOKEN")
	doDomain = os.Getenv("DIGITALOCEAN_DOMAIN")
	if len(doToken) > 0 && len(doDomain) > 0 {
		doLiveTest = true
	}
}

func TestNewDNSProviderValid(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "")
	_, err := NewDNSProviderCredentials("123", util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "")
	_, err := NewDNSProvider(util.RecursiveNameservers, "cert-manager-test")
	assert.EqualError(t, err, "DigitalOcean token missing")
}

func TestDigitalOceanPresent(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(doToken, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)

	err = provider.Present(t.Context(), doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestDigitalOceanCleanUp(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(doToken, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err)

	err = provider.CleanUp(t.Context(), doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestNewDNSProviderFromOptions(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		options []DNSProviderOption
		wantErr string
	}{
		{
			name: "valid token",
			options: []DNSProviderOption{
				Token("123"),
				Nameservers(util.RecursiveNameservers),
				UserAgent("cert-manager-test"),
				Resolver(util.NewCachingResolver()),
			},
		},
		{
			name: "missing token",
			options: []DNSProviderOption{
				Nameservers(util.RecursiveNameservers),
				UserAgent("cert-manager-test"),
				Resolver(util.NewCachingResolver()),
			},
			wantErr: "DigitalOcean token missing",
		},
		{
			name: "missing resolver",
			options: []DNSProviderOption{
				Token("123"),
				Nameservers(util.RecursiveNameservers),
			},
			wantErr: "resolver is required",
		},
		{
			name: "missing nameservers",
			options: []DNSProviderOption{
				Token("123"),
				Resolver(util.NewCachingResolver()),
			},
			wantErr: "nameservers is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}
			_, err := NewDNSProviderFromOptions(t.Context(), tt.options...)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
