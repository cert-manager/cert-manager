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

package softlayer

import (
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	softlayerUsername string
	softlayerAPIKey   string
)

func init() {
	softlayerUsername = "unittest"
	softlayerAPIKey = "unittest-token"
}

func TestSoftlayerPresent(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	registerMocks(t)

	provider, err := NewDNSProviderCredentials(softlayerUsername, softlayerAPIKey, util.RecursiveNameservers)
	assert.NoError(t, err)

	domain := "example.com"
	err = provider.Present(domain, "_acme-challenge."+domain+".", "123d==")
	assert.NoError(t, err)

	info := httpmock.GetCallCountInfo()
	assert.Equal(t, info[`POST =~^https://api\.softlayer\.com/rest/v3/SoftLayer_Dns_Domain/(\d+)/createTxtRecord\.json`], 1)
	assert.Equal(t, info["GET https://api.softlayer.com/rest/v3/SoftLayer_Account/getDomains.json"], 1)
	assert.Equal(t, info[`GET =~^https://api\.softlayer\.com/rest/v3/SoftLayer_Dns_Domain/(\d+)/getResourceRecords.json`], 2)
}

func TestSoftlayerPresentDelete(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	registerMocks(t)

	provider, err := NewDNSProviderCredentials(softlayerUsername, softlayerAPIKey, util.RecursiveNameservers)
	assert.NoError(t, err)

	domain := "example.net"
	err = provider.Present(domain, "_acme-challenge."+domain+".", "123d==")
	assert.NoError(t, err)

	info := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, info[`POST https://api.softlayer.com/rest/v3/SoftLayer_Dns_Domain_ResourceRecord/deleteObjects.json`])
}

func TestSoftlayerCleanUp(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	registerMocks(t)

	provider, err := NewDNSProviderCredentials(softlayerUsername, softlayerAPIKey, util.RecursiveNameservers)
	assert.NoError(t, err)

	domain := "example.net"
	err = provider.CleanUp(domain, "_acme-challenge."+domain+".", "123d==")
	assert.NoError(t, err)

	info := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, info[`POST https://api.softlayer.com/rest/v3/SoftLayer_Dns_Domain_ResourceRecord/deleteObjects.json`])
}
