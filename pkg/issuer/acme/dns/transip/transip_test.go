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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

const sampleZoneData = `{
    "token": "a184671d5307a388180fbf7f11dbdf46",
    "zone": {
        "name": "example.com",
        "soa": {
            "contact": "hostmaster.transip.com.",
            "expire": 604800,
            "minimum": 180,
            "originserver": "use4.transip.com.",
            "refresh": 900,
            "retry": 300,
            "serial": 1271354824,
            "ttl": 900
        },
        "ns": [
            {
                "active": true,
                "name": "",
                "target": "use4.akam.net.",
                "ttl": 3600
            },
            {
                "active": true,
                "name": "",
                "target": "use3.akam.net.",
                "ttl": 3600
            }
        ]
    }
}`

const sampleZoneDataWithTxt = `{
    "token": "a184671d5307a388180fbf7f11dbdf46",
    "zone": {
        "name": "example.com",
        "soa": {
            "contact": "hostmaster.transip.com.",
            "expire": 604800,
            "minimum": 180,
            "originserver": "use4.transip.com.",
            "refresh": 900,
            "retry": 300,
            "serial": 1271354825,
            "ttl": 900
        },
        "ns": [
            {
                "active": true,
                "name": "",
                "target": "use4.akam.net.",
                "ttl": 3600
            },
            {
                "active": true,
                "name": "",
                "target": "use3.akam.net.",
                "ttl": 3600
            }
        ],
        "txt": [
            {
                "active": true,
                "name" :"_acme-challenge.test",
                "target": "dns01-key",
                "ttl": 60
            }
        ]
    }
}`

type httpResponder func(req *http.Request) (*http.Response, error)

func (r httpResponder) RoundTrip(req *http.Request) (*http.Response, error) {
	return r(req)
}

//NewDNSProvider(accountName string, PrivateKey []byte, dns01Nameservers []string) (*DNSProvider, error) {

func TestPresent(t *testing.T) {
	transip, err := NewDNSProvider("exampleaccount", "token", util.RecursiveNameservers)
	assert.NoError(t, err)

	var response []byte
	mockTransport(t, transip, "example.com", sampleZoneData, &response)

	assert.NoError(t, transip.Present("test.example.com", "dns01-token", "dns01-key"))

	var expected, actual map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(sampleZoneDataWithTxt), &expected))
	assert.NoError(t, json.Unmarshal(response, &actual))
	assert.EqualValues(t, expected, actual)
}

func TestCleanUp(t *testing.T) {
	transip, err := NewDNSProvider("transip.example.com", "token", util.RecursiveNameservers)
	assert.NoError(t, err)

	var response []byte
	mockTransport(t, transip, "example.com", sampleZoneDataWithTxt, &response)

	assert.NoError(t, transip.CleanUp("test.example.com", "dns01-token", "dns01-key"))

	var expected, actual map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(sampleZoneData), &expected))
	expected["zone"].(map[string]interface{})["soa"].(map[string]interface{})["serial"] = 1271354826.
	assert.NoError(t, json.Unmarshal(response, &actual))
	assert.EqualValues(t, expected, actual)
}

func mockTransport(t *testing.T, transip *DNSProvider, domain, data string, response *[]byte) {
	transip.transport = httpResponder(func(req *http.Request) (*http.Response, error) {
		defer req.Body.Close()

		if req.URL.String() != "https://transip.example.com/config-dns/v1/zones/"+domain {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       http.NoBody,
			}, nil
		}

		if req.Method == http.MethodGet {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(data))),
			}, nil
		}

		if req.Method == http.MethodPost {
			if req.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("usupported Content Type: %v", req.Header.Get("Content-Type"))
			}

			var err error
			*response, err = ioutil.ReadAll(req.Body)
			assert.NoError(t, err)

			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       http.NoBody,
			}, nil
		}

		t.Fatalf("unexpected method: %v", req.Method)
		return nil, nil
	})
	transip.findHostedDomainByFqdn = func(fqdn string) (string, error) {
		if !strings.HasSuffix(fqdn, domain+".") {
			t.Fatalf("unexpected fqdn: %s", fqdn)
		}
		return domain, nil
	}
}
