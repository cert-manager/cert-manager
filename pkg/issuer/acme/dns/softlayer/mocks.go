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
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/softlayer/softlayer-go/datatypes"
	"github.com/stretchr/testify/assert"
)

var (
	domains map[int]datatypes.Dns_Domain
)

func init() {
	domains = map[int]datatypes.Dns_Domain{}
	domainID := 123123
	domainName := "example.com"
	domains[domainID] = datatypes.Dns_Domain{Id: &domainID, Name: &domainName}
	domainIDNew := 321321
	domainNameNew := "example.net"
	domains[domainIDNew] = datatypes.Dns_Domain{Id: &domainIDNew, Name: &domainNameNew}
}

func parseFilter(filterString string) (map[string]map[string]map[string]string, error) {
	var filter map[string]map[string]map[string]string

	if filterString == "" {
		return filter, nil
	}
	err := json.Unmarshal([]byte(filterString), &filter)

	if err != nil {
		return nil, err
	}
	return filter, nil
}

func registerMocks(t *testing.T) {
	httpmock.RegisterResponder("GET", "https://api.softlayer.com/rest/v3/SoftLayer_Account/getDomains.json",
		func(req *http.Request) (*http.Response, error) {
			filter, err := parseFilter(req.URL.Query().Get("objectFilter"))
			if err != nil {
				return nil, err
			}

			query := filter["domains"]["name"]["operation"]

			for _, domain := range domains {
				if strings.TrimRight(query, ".") == *domain.Name {
					return httpmock.NewJsonResponse(200, []datatypes.Dns_Domain{domain})
				}
			}
			return httpmock.NewJsonResponse(404, nil)
		},
	)

	httpmock.RegisterResponder("GET", `=~^https://api\.softlayer\.com/rest/v3/SoftLayer_Dns_Domain/(\d+)/getResourceRecords.json`,
		func(req *http.Request) (*http.Response, error) {
			filter, err := parseFilter(req.URL.Query().Get("objectFilter"))

			if err != nil {
				return nil, err
			}

			queryHost := filter["resourceRecords"]["host"]["operation"]
			queryType := filter["resourceRecords"]["type"]["operation"]

			id := httpmock.MustGetSubmatchAsUint(req, 1)

			recordHost := "test"
			recordData := "123"
			recordType := "a"
			aRecord := datatypes.Dns_Domain_ResourceRecord{Type: &recordType, Host: &recordHost, Data: &recordData}

			if queryHost == "" && queryType == "" {
				return httpmock.NewJsonResponse(200, []datatypes.Dns_Domain_ResourceRecord{aRecord})
			}

			if id == 123123 {
				return httpmock.NewJsonResponse(200, []datatypes.Dns_Domain_ResourceRecord{})
			}

			if id == 321321 {
				recordHost := "_acme-challenge"
				recordData := "123"
				recordType := "txt"
				aRecord := datatypes.Dns_Domain_ResourceRecord{Type: &recordType, Host: &recordHost, Data: &recordData}
				return httpmock.NewJsonResponse(200, []datatypes.Dns_Domain_ResourceRecord{aRecord})
			}

			return httpmock.NewJsonResponse(404, nil)
		},
	)

	httpmock.RegisterResponder("POST", `=~^https://api\.softlayer\.com/rest/v3/SoftLayer_Dns_Domain/(\d+)/createTxtRecord\.json`,
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, req.Header["Authorization"], []string{"Basic dW5pdHRlc3Q6dW5pdHRlc3QtdG9rZW4="})
			id := httpmock.MustGetSubmatchAsUint(req, 1)

			recordData := "123d=="
			recordID := int(id)

			if val, ok := domains[recordID]; ok {
				record := datatypes.Dns_Domain_ResourceRecord_TxtType{Dns_Domain_ResourceRecord: datatypes.Dns_Domain_ResourceRecord{Id: &recordID, Data: &recordData, Host: val.Name}}
				return httpmock.NewJsonResponse(200, record)
			}
			return httpmock.NewJsonResponse(404, nil)
		},
	)

	httpmock.RegisterResponder("POST", "https://api.softlayer.com/rest/v3/SoftLayer_Dns_Domain_ResourceRecord/deleteObjects.json",
		func(req *http.Request) (*http.Response, error) {

			return httpmock.NewJsonResponse(200, true)
		},
	)
}
