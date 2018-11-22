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

package transip

import (
	"cert-manager/bazel-cert-manager/external/go_sdk/src/fmt"
	"github.com/transip/gotransip/domain"
	"testing"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)


const fqdn = "_acme-challenge.test.example.com."
const dn = "test.example.com"




func TestPresent(t *testing.T) {

	fmt.Println(util.RecursiveNameservers)

	transip, err := NewDNSProvider("exampleaccount", []byte("token"), util.RecursiveNameservers)
	assert.NoError(t, err)

	assert.NoError(t, mockup(t, transip))

	a,b,err := transip.findDomain(dn)
	assert.NoError(t, err, "failure finding domain")
	fmt.Println(a)
	fmt.Println(b)

	entries, err := transip.changeRecord(dn, fqdn, "dns01-token", 60)
	assert.NoError(t, err)
	assert.EqualValues(t, 1, len(entries))
	assert.EqualValues(t, "_acme-challenge.test", entries[0].Name)
	assert.EqualValues(t, "dns01-token", entries[0].Content)


}

func TestCleanUp(t *testing.T) {

	transip, err := NewDNSProvider("exampleaccount", []byte("token"), util.RecursiveNameservers)
	assert.NoError(t, err)

	assert.NoError(t, mockup(t, transip))

	a,b,err := transip.findDomain(dn)
	assert.NoError(t, err, "failure finding domain")
	fmt.Println(a)
	fmt.Println(b)

	entries, err := transip.changeRecord(dn, fqdn, "dns01-token", 0)
	assert.NoError(t, err)
	assert.EqualValues(t, 0, len(entries))


}




func TestLive(t *testing.T) {

	var accountName = ""
	var privateKey = []byte("")
	var domain = "example.com"
	var subdomain = "test." + domain

	var value = "dnstest_333452452345234"


	if (accountName != "") {

		transip, err := NewDNSProvider(accountName, privateKey, util.RecursiveNameservers)
		assert.NoError(t, err)

		//assert.NoError(t, mockup(t, transip))

		transip.waitTime = 1

		err = transip.Present(domain, "", value)
		assert.NoError(t, err, "failure adding to domain")

		err = transip.Present(subdomain, "", value)
		assert.NoError(t, err, "failure adding to subdomain")

		err = transip.CleanUp(domain, "", value)
		assert.NoError(t, err, "failure removing from domain")

		err = transip.CleanUp(subdomain, "", value)
		assert.NoError(t, err, "failure removing from subdomain")
	} else {
		t.Skipf("Skipped live testing, no accountname set")
	}


}



func mockup(t *testing.T, transip *DNSProvider) (error) {

	transip.mockup = true

	var domExample = domain.Domain{}

	domExample.Name = "example.com"
	domExample.DNSEntries = append(domExample.DNSEntries, domain.DNSEntry{
		"_acme-challenge.test",
		3600,
		"TXT",
		"dns01-token",
	})

	transip.mockupDomains = append(
		transip.mockupDomains,
		domExample,
	)


	return nil

}

