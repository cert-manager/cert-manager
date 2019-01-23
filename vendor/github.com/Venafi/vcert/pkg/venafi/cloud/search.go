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

package cloud

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type SearchRequest struct {
	Expression *Expression  `json:"expression"`
	Ordering   *interface{} `json:"ordering,omitempty"`
	Paging     *Paging      `json:"paging,omitempty"`
	// ordering is not used here so far
	// "ordering": {"orders": [{"direction": "ASC", "field": "subjectCN"},{"direction": "DESC", "field": "keyStrength"}]},
}

type Expression struct {
	Operands []Operand `json:"operands,omitempty"`
}

type Operand struct {
	Field    Field       `json:"field"`
	Operator Operator    `json:"operator"`
	Value    interface{} `json:"value"`
}

type Field string
type Operator string

type Paging struct {
	PageNumber int `json:"pageNumber"`
	PageSize   int `json:"pageSize"`
}

const (
	EQ    Operator = "EQ"
	FIND           = "FIND"
	GT             = "GT"
	GTE            = "GTE"
	IN             = "IN"
	LT             = "LT"
	LTE            = "LTE"
	MATCH          = "MATCH"
)

type CertificateSearchResponse struct {
	Count        int           `json:"count"`
	Certificates []Certificate `json:"certificates"`
}

type Certificate struct {
	Id                   string   `json:"id"`
	ManagedCertificateId string   `json:"managedCertificateId"`
	CertificateRequestId string   `json:"certificateRequestId"`
	SubjectCN            []string `json:"subjectCN"`
	/*...and many more fields... */
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
			respErrors, err := parseResponseErrors(body)
			if err == nil {
				respError := fmt.Sprintf("Unexpected status code on Venafi Cloud certificate search. Status: %d\n", httpStatusCode)
				for _, e := range respErrors {
					respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
				}
				return nil, fmt.Errorf(respError)
			}
		}
		return nil, fmt.Errorf("Unexpected status code on Venafi Cloud certificate search. Status: %d", httpStatusCode)
	}
}
