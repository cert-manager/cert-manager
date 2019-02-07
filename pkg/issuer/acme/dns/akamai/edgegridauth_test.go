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

package akamai

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDataToSign(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		"https://akaa-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net/diagnostic-tools/v1/locations",
		http.NoBody)
	assert.NoError(t, err)

	auth := NewEdgeGridAuth("ClientToken", "ClientSecret", "AccessToken")
	auth.now = func() time.Time {
		return time.Unix(1396461906, 0) // 20140402T18:05:06Z
	}
	auth.createNonce = func() (string, error) {
		return "185f94eb-537c-4c01-b8cc-2fa5a06aee7f", nil
	}

	data, err := auth.signingData(req)
	assert.NoError(t, err)

	expected := "GET" +
		"\thttps" +
		"\takaa-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net" +
		"\t/diagnostic-tools/v1/locations" +
		"\t" + // headers
		"\t" + // content hash
		"\tEG1-HMAC-SHA256 " +
		"client_token=ClientToken;" +
		"access_token=AccessToken;" +
		"timestamp=20140402T18:05:06+0000;" +
		"nonce=185f94eb-537c-4c01-b8cc-2fa5a06aee7f;"

	assert.EqualValues(t, expected, data.dataToSign)
}

func TestDataToSignWithHeaders(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		"http://akaa-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna-dev.akamaiapis.net/sample-api/v1/property/?fields=x&format=json&cpcode=1234",
		http.NoBody)
	assert.NoError(t, err)

	req.Header.Set("x-a", "va")
	req.Header.Set("x-c", "\"      xc        \"")
	req.Header.Set("x-b", "   w         b")

	auth := NewEdgeGridAuth(
		"ClientToken", "ClientSecret", "AccessToken",
		"x-c", "x-b", "x-a")
	auth.now = func() time.Time {
		return time.Unix(1376917283, 0) // 20130819T13:01:23Z
	}
	auth.createNonce = func() (string, error) {
		return "ac392096-8aa1-44fd-8c3b-f797d35a6736", nil
	}

	data, err := auth.signingData(req)
	assert.NoError(t, err)

	expected := "GET" +
		"\thttp" +
		"\takaa-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna-dev.akamaiapis.net" +
		"\t/sample-api/v1/property/?fields=x&format=json&cpcode=1234" +
		"\tx-a:va\tx-b:w b\tx-c:\" xc \"\t" +
		"\t" + // content hash
		"\tEG1-HMAC-SHA256 " +
		"client_token=ClientToken;" +
		"access_token=AccessToken;" +
		"timestamp=20130819T13:01:23+0000;" +
		"nonce=ac392096-8aa1-44fd-8c3b-f797d35a6736;"

	assert.EqualValues(t, expected, data.dataToSign)
}
