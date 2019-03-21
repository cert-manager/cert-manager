/*
 * Copyright 2018 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tpp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type SearchRequest []string

type CertificateSearchResponse struct {
	Certificates []Certificate `json:"Certificates"`
	Count        int           `json:"TotalCount"`
}

type Certificate struct {
	//Id                   string   `json:"DN"`
	//ManagedCertificateId string   `json:"DN"`
	CertificateRequestId string `json:"DN"`
	/*...and some more fields... */
}

func (c *Connector) searchCertificatesByFingerprint(fp string) (*CertificateSearchResponse, error) {
	fp = strings.Replace(fp, ":", "", -1)
	fp = strings.Replace(fp, ".", "", -1)
	fp = strings.ToUpper(fp)

	var req SearchRequest
	req = append(req, fmt.Sprintf("Thumbprint=%s", fp))

	return c.searchCertificates(&req)
}

func (c *Connector) searchCertificates(req *SearchRequest) (*CertificateSearchResponse, error) {

	var err error

	url := fmt.Sprintf("%s?%s", urlResourceCertificateSearch, strings.Join(*req, "&"))
	statusCode, _, body, err := c.request("GET", urlResource(url), nil)
	if err != nil {
		return nil, err
	}
	searchResult, err := ParseCertificateSearchResponse(statusCode, body)
	if err != nil {
		return nil, err
	}
	return searchResult, nil
}

func ParseCertificateSearchResponse(httpStatusCode int, body []byte) (searchResult *CertificateSearchResponse, err error) {
	switch httpStatusCode {
	case http.StatusOK:
		var searchResult = &CertificateSearchResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse search results: %s, body: %s", err, body)
		}
		return searchResult, nil
	default:
		if body != nil {
			return nil, NewResponseError(body)
		} else {
			return nil, fmt.Errorf("Unexpected status code on certificate search. Status: %d", httpStatusCode)
		}
	}
}
