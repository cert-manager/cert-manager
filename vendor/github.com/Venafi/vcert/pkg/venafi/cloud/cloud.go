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
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type apiKey struct {
	Username                string    `json:"username,omitempty"`
	APITypes                []string  `json:"apitypes,omitempty"`
	APIVersion              string    `json:"apiVersion,omitempty"`
	APIKeyStatus            string    `json:"apiKeyStatus,omitempty"`
	CreationDateString      string    `json:"creationDate,omitempty"`
	CreationDate            time.Time `json:"-"`
	ValidityStartDateString string    `json:"validityStartDate,omitempty"`
	ValidityStartDate       time.Time `json:"-"`
	ValidityEndDateString   string    `json:"validityEndDate,omitempty"`
	ValidityEndDate         time.Time `json:"-"`
}

type userDetails struct {
	User    *user    `json:"user,omitempty"`
	Company *company `json:"company,omitempty"`
	APIKey  *apiKey  `json:"apiKey,omitempty"`
}

type certificateRequestResponse struct {
	CertificateRequests []certificateRequestResponseData `json:"certificateRequests,omitempty"`
}

type certificateRequestResponseData struct {
	ID                     string    `json:"id,omitempty"`
	ZoneID                 string    `json:"zoneId,omitempty"`
	Status                 string    `json:"status,omitempty"`
	SubjectDN              string    `json:"subjectDN,omitempty"`
	GeneratedKey           bool      `json:"generatedKey,omitempty"`
	DefaultKeyPassword     bool      `json:"defaultKeyPassword,omitempty"`
	CertificateInstanceIDs []string  `json:"certificateInstanceIds,omitempty"`
	CreationDateString     string    `json:"creationDate,omitempty"`
	CreationDate           time.Time `json:"-"`
	PEM                    string    `json:"pem,omitempty"`
	DER                    string    `json:"der,omitempty"`
}

type certificateRequest struct { // TODO: this is actually certificate request object (sent with POST)
	//CompanyID      string `json:"companyId,omitempty"`
	CSR                          string `json:"certificateSigningRequest,omitempty"`
	ZoneID                       string `json:"zoneId,omitempty"`
	ExistingManagedCertificateId string `json:"existingManagedCertificateId,omitempty"`
	ReuseCSR                     bool   `json:"reuseCSR,omitempty"`
	//DownloadFormat string `json:"downloadFormat,omitempty"`
}

type certificateStatus struct { // TODO: this is actually the same certificate request object (received with GET)
	Id                        string                            `json:"Id,omitempty"`
	ManagedCertificateId      string                            `json:"managedCertificateId,omitempty"`
	ZoneId                    string                            `json:"zoneId,omitempty"`
	Status                    string                            `json:"status,omitempty"`
	ErrorInformation          CertificateStatusErrorInformation `json:"errorInformation,omitempty"`
	CreationDate              string                            `json:"creationDate,omitempty"`
	ModificationDate          string                            `json:"modificationDate,omitempty"`
	CertificateSigningRequest string                            `json:"certificateSigningRequest,omitempty"`
	SubjectDN                 string                            `json:"subjectDN,omitempty"`
}

type CertificateStatusErrorInformation struct {
	Type    string   `json:"type,omitempty"`
	Code    int      `json:"code,omitempty"`
	Message string   `json:"message,omitempty"`
	Args    []string `json:"args,omitempty"`
}

//GenerateRequest generates a CertificateRequest based on the zone configuration, and returns the request along with the private key.
func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {
	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		var pk interface{}
		if config == nil {
			config, err = c.ReadZoneConfiguration(c.zone)
			if err != nil {
				return fmt.Errorf("could not read zone configuration: %s", err)
			}
		}
		err = config.ValidateCertificateRequest(req)
		if err != nil {
			return err
		}
		config.UpdateCertificateRequest(req)
		switch req.KeyType {
		case certificate.KeyTypeECDSA:
			pk, err = certificate.GenerateECDSAPrivateKey(req.KeyCurve)
		case certificate.KeyTypeRSA:
			pk, err = certificate.GenerateRSAPrivateKey(req.KeyLength)
		default:
			return fmt.Errorf("Unable to generate certificate request, key type %s is not supported", req.KeyType.String())
		}
		if err != nil {
			return err
		}
		req.PrivateKey = pk
		err = certificate.GenerateRequest(req, pk)
		if err != nil {
			return err
		}
		req.CSR = pem.EncodeToMemory(certificate.GetCertificateRequestPEMBlock(req.CSR))
		return nil

	case certificate.UserProvidedCSR:
		if req.CSR == nil || len(req.CSR) == 0 {
			return fmt.Errorf("CSR was supposed to be provided by user, but it's empty")
		}
		return nil

	case certificate.ServiceGeneratedCSR:
		req.CSR = nil
		return nil

	default:
		return fmt.Errorf("unrecognised req.CsrOrigin %v", req.CsrOrigin)
	}
}

//SetBaseURL allows overriding the default URL used to communicate with Venafi Cloud
func (c *Connector) SetBaseURL(url string) error {
	if url == "" {
		return fmt.Errorf("base URL cannot be empty")
	}
	modified := strings.ToLower(url)
	reg := regexp.MustCompile("^http(|s)://")
	if reg.FindStringIndex(modified) == nil {
		modified = "https://" + modified
	} else {
		modified = reg.ReplaceAllString(modified, "https://")
	}
	reg = regexp.MustCompile("/v1(|/)$")
	if reg.FindStringIndex(modified) == nil {
		modified += "v1/"
	} else {
		modified = reg.ReplaceAllString(modified, "/v1/")
	}
	c.baseURL = modified
	return nil
}

func (c *Connector) getURL(resource urlResource) string {
	return fmt.Sprintf("%s%s", c.baseURL, resource)
}

func parseUserDetailsResult(expectedStatusCode int, httpStatusCode int, httpStatus string, body []byte) (*userDetails, error) {
	if httpStatusCode == expectedStatusCode {
		resp, err := parseUserDetailsData(body)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	switch httpStatusCode {
	case http.StatusConflict, http.StatusPreconditionFailed:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud registration. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, fmt.Errorf(respError)
	default:
		if body != nil {
			respErrors, err := parseResponseErrors(body)
			if err == nil {
				respError := fmt.Sprintf("Unexpected status code on Venafi Cloud registration. Status: %s\n", httpStatus)
				for _, e := range respErrors {
					respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
				}
				return nil, fmt.Errorf(respError)
			}
		}
		return nil, fmt.Errorf("Unexpected status code on Venafi Cloud registration. Status: %s", httpStatus)
	}
}

func parseUserDetailsData(b []byte) (*userDetails, error) {
	var data userDetails
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func parseZoneConfigurationResult(httpStatusCode int, httpStatus string, body []byte) (*zone, error) {
	switch httpStatusCode {
	case http.StatusOK:
		z, err := parseZoneConfigurationData(body)
		if err != nil {
			return nil, err
		}
		return z, nil
	case http.StatusBadRequest, http.StatusPreconditionFailed, http.StatusNotFound:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud zone read. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, fmt.Errorf(respError)
	default:
		if body != nil {
			respErrors, err := parseResponseErrors(body)
			if err == nil {
				respError := fmt.Sprintf("Unexpected status code on Venafi Cloud zone read. Status: %s\n", httpStatus)
				for _, e := range respErrors {
					respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
				}
				return nil, fmt.Errorf(respError)
			}
		}
		return nil, fmt.Errorf("Unexpected status code on Venafi Cloud zone read. Status: %s", httpStatus)
	}
}

func parseZoneConfigurationData(b []byte) (*zone, error) {
	var data zone
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func parseCertificatePolicyResult(httpStatusCode int, httpStatus string, body []byte) (*certificatePolicy, error) {
	switch httpStatusCode {
	case http.StatusOK:
		p, err := parseCertificatePolicyData(body)
		if err != nil {
			return nil, err
		}
		return p, nil
	case http.StatusBadRequest, http.StatusPreconditionFailed, http.StatusNotFound:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud policy read. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, fmt.Errorf(respError)
	default:
		if body != nil {
			respErrors, err := parseResponseErrors(body)
			if err == nil {
				respError := fmt.Sprintf("Unexpected status code on Venafi Cloud policy read. Status: %s\n", httpStatus)
				for _, e := range respErrors {
					respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
				}
				return nil, fmt.Errorf(respError)
			}
		}
		return nil, fmt.Errorf("Unexpected status code on Venafi Cloud policy read. Status: %s", httpStatus)
	}
}

func parseCertificatePolicyData(b []byte) (*certificatePolicy, error) {
	var data certificatePolicy
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func parseCertificateRequestResult(httpStatusCode int, httpStatus string, body []byte) (*certificateRequestResponse, error) {
	switch httpStatusCode {
	case http.StatusCreated:
		z, err := parseCertificateRequestData(body)
		if err != nil {
			return nil, err
		}
		return z, nil
	case http.StatusBadRequest, http.StatusPreconditionFailed:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		respError := fmt.Sprintf("Certificate request failed with server error. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, fmt.Errorf(respError)
	default:
		if body != nil {
			respErrors, err := parseResponseErrors(body)
			if err == nil {
				respError := fmt.Sprintf("Unexpected status code on Venafi Cloud certificate request. Status: %s\n", httpStatus)
				for _, e := range respErrors {
					respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
				}
				return nil, fmt.Errorf(respError)
			}
		}
		return nil, fmt.Errorf("Unexpected status code on Venafi Cloud certificate request. Status: %s", httpStatus)
	}
}

func parseCertificateRequestData(b []byte) (*certificateRequestResponse, error) {
	var data certificateRequestResponse
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func newPEMCollectionFromResponse(data []byte, chainOrder certificate.ChainOption) (*certificate.PEMCollection, error) {
	return certificate.PEMCollectionFromBytes(data, chainOrder)
}
