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

package hetzner

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	doLiveTest bool
	doToken    string
	doDomain   string
)

func init() {
	doToken = os.Getenv("HETZNER_TOKEN")
	doDomain = os.Getenv("HETZNER_DOMAIN")
	if len(doToken) > 0 && len(doDomain) > 0 {
		doLiveTest = true
	}
}

func restoreEnv() {
	os.Setenv("HETZNER_TOKEN", doToken)
}

func TestNewDNSProviderValid(t *testing.T) {
	os.Setenv("HETZNER_TOKEN", "")
	_, err := NewDNSProviderCredentials("123", util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreEnv()
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	os.Setenv("HETZNER_TOKEN", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("HETZNER_TOKEN", "")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.EqualError(t, err, "Hetzner token missing")
	restoreEnv()
}

func TestHetznerPresent(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(doToken, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestHetznerCleanUp(t *testing.T) {
	if !doLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(doToken, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(doDomain, "_acme-challenge."+doDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestHetznerSolveForProvider(t *testing.T) {

}
