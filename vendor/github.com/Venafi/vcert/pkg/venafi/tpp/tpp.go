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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"net/http"
	"regexp"
	"strings"
)

const defaultKeySize = 2048
const defaultSignatureAlgorithm = x509.SHA256WithRSA

type certificateRequest struct {
	PolicyDN                string          `json:",omitempty"`
	CADN                    string          `json:",omitempty"`
	ObjectName              string          `json:",omitempty"`
	Subject                 string          `json:",omitempty"`
	OrganizationalUnit      string          `json:",omitempty"`
	Organization            string          `json:",omitempty"`
	City                    string          `json:",omitempty"`
	State                   string          `json:",omitempty"`
	Country                 string          `json:",omitempty"`
	SubjectAltNames         []sanItem       `json:",omitempty"`
	Contact                 string          `json:",omitempty"`
	CASpecificAttributes    []nameValuePair `json:",omitempty"`
	PKCS10                  string          `json:",omitempty"`
	KeyAlgorithm            string          `json:",omitempty"`
	KeyBitSize              int             `json:",omitempty"`
	EllipticCurve           string          `json:",omitempty"`
	DisableAutomaticRenewal bool            `json:",omitempty"`
}

type certificateRetrieveRequest struct {
	CertificateDN     string `json:",omitempty"`
	Format            string `json:",omitempty"`
	Password          string `json:",omitempty"`
	IncludePrivateKey bool   `json:",omitempty"`
	IncludeChain      bool   `json:",omitempty"`
	FriendlyName      string `json:",omitempty"`
	RootFirstOrder    bool   `json:",omitempty"`
}

type certificateRetrieveResponse struct {
	CertificateData string `json:",omitempty"`
	Format          string `json:",omitempty"`
	Filename        string `json:",omitempty"`
	Status          string `json:",omitempty"`
	Stage           int    `json:",omitempty"`
}

type RevocationReason int

// this maps *certificate.RevocationRequest.Reason to TPP-specific webSDK codes
var RevocationReasonsMap = map[string]RevocationReason{
	"":                       0, // NoReason
	"none":                   0, //
	"key-compromise":         1, // UserKeyCompromised
	"ca-compromise":          2, // CAKeyCompromised
	"affiliation-changed":    3, // UserChangedAffiliation
	"superseded":             4, // CertificateSuperseded
	"cessation-of-operation": 5, // OriginalUseNoLongerValid
}

type certificateRevokeRequest struct {
	CertificateDN string           `json:",omitempty"`
	Thumbprint    string           `json:",omitempty"`
	Reason        RevocationReason `json:",omitempty"`
	Comments      string           `json:",omitempty"`
	Disable       bool             `json:",omitempty"`
}

/* {Requested:true  Success:true Error:} -- means requested
   {Requested:false Success:true Error:} -- means already revoked  */
type certificateRevokeResponse struct {
	Requested bool   `json:",omitempty"`
	Success   bool   `json:",omitempty"`
	Error     string `json:",omitempty"`
}

type certificateRenewRequest struct {
	CertificateDN string `json:",omitempty"`
	PKCS10        string `json:",omitempty"`
}

type certificateRenewResponse struct {
	Success bool   `json:",omitempty"`
	Error   string `json:",omitempty"`
}

type sanItem struct {
	Type int    `json:",omitempty"`
	Name string `json:",omitempty"`
}

type nameValuePair struct {
	Name  string `json:",omitempty"`
	Value string `json:",omitempty"`
}

type certificateRequestResponse struct {
	CertificateDN string `json:",omitempty"`
	Error         string `json:",omitempty"`
}

type authorizeResponse struct {
	APIKey     string `json:",omitempty"`
	ValidUntil string `json:",omitempty"`
}

type authorizeResquest struct {
	Username string `json:",omitempty"`
	Password string `json:",omitempty"`
}

type policyRequest struct {
	ObjectDN      string `json:",omitempty"`
	Class         string `json:",omitempty"`
	AttributeName string `json:",omitempty"`
}

type urlResource string

const (
	urlResourceAuthorize           urlResource = "authorize/"
	urlResourceCertificateRequest              = "certificates/request"
	urlResourceCertificateRetrieve             = "certificates/retrieve"
	urlResourceFindPolicy                      = "config/findpolicy"
	urlResourceCertificateRevoke               = "certificates/revoke"
	urlResourceCertificateRenew                = "certificates/renew"
	urlResourceCertificateSearch               = "certificates/"
	urlResourceCertificateImport               = "certificates/import"
)

const (
	tppAttributeOrg            = "Organization"
	tppAttributeOrgUnit        = "Organizational Unit"
	tppAttributeCountry        = "Country"
	tppAttributeState          = "State"
	tppAttributeLocality       = "City"
	tppAttributeKeyAlgorithm   = "Key Algorithm"
	tppAttributeKeySize        = "Key Bit Strength"
	tppAttributeEllipticCurve  = "Elliptic Curve"
	tppAttributeRequestHash    = "PKCS10 Hash Algorithm"
	tppAttributeManagementType = "Management Type"
	tppAttributeManualCSR      = "Manual Csr"
)

type tppPolicyData struct {
	Error  string   `json:",omitempty"`
	Result int      `json:",omitempty"`
	Values []string `json:",omitempty"`
	Locked bool     `json:",omitempty"`
}

type retrieveChainOption int

const (
	retrieveChainOptionRootLast retrieveChainOption = iota
	retrieveChainOptionRootFirst
	retrieveChainOptionIgnore
)

const (
	pkcs10HashAlgorithmSha1   = 0
	pkcs10HashAlgorithmSha256 = 1
	pkcs10HashAlgorithmSha384 = 2
	pkcs10HashAlgorithmSha512 = 3
)

func retrieveChainOptionFromString(order string) retrieveChainOption {
	switch strings.ToLower(order) {
	case "root-first":
		return retrieveChainOptionRootFirst
	case "ignore":
		return retrieveChainOptionIgnore
	default:
		return retrieveChainOptionRootLast
	}
}

// SetBaseURL sets the base URL used to cummuncate with TPP
func (c *Connector) SetBaseURL(url string) error {
	modified := strings.ToLower(url)
	reg := regexp.MustCompile("^http(|s)://")
	if reg.FindStringIndex(modified) == nil {
		modified = "https://" + modified
	} else {
		modified = reg.ReplaceAllString(modified, "https://")
	}
	reg = regexp.MustCompile("^https://.+?/")
	if reg.FindStringIndex(modified) == nil {
		modified = modified + "/"
	}

	reg = regexp.MustCompile("/vedsdk(|/)$")
	if reg.FindStringIndex(modified) == nil {
		modified += "vedsdk/"
	} else {
		modified = reg.ReplaceAllString(modified, "/vedsdk/")
	}

	reg = regexp.MustCompile("^https://[a-z\\d]+[-a-z\\d.]+[a-z\\d][:\\d]*/vedsdk/$")
	if loc := reg.FindStringIndex(modified); loc == nil {
		return fmt.Errorf("The specified TPP URL is invalid. %s\nExpected TPP URL format 'https://tpp.company.com/vedsdk/'", url)
	}

	c.baseURL = modified
	return nil
}

func (c *Connector) getURL(resource urlResource) (string, error) {
	if c.baseURL == "" {
		return "", fmt.Errorf("The Host URL has not been set")
	}
	return fmt.Sprintf("%s%s", c.baseURL, resource), nil
}

func (c *Connector) getHTTPClient() *http.Client {
	if c.trust != nil {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: c.trust}}
		return &http.Client{Transport: tr}
	}

	return http.DefaultClient
}

//GenerateRequest creates a new certificate request, based on the zone/policy configuration and the user data
func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {
	if config == nil {
		config, err = c.ReadZoneConfiguration(c.zone)
		if err != nil {
			return fmt.Errorf("could not read zone configuration: %s", err)
		}
	}

	tppMgmtType := config.CustomAttributeValues[tppAttributeManagementType]
	if tppMgmtType == "Monitoring" || tppMgmtType == "Unassigned" {
		return fmt.Errorf("Unable to request certificate from TPP, current TPP configuration would not allow the request to be processed")
	}

	config.UpdateCertificateRequest(req)

	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		if config.CustomAttributeValues[tppAttributeManualCSR] == "0" {
			return fmt.Errorf("Unable to request certificate by local generated CSR when zone configuration is 'Manual Csr' = 0")
		}
		switch req.KeyType {
		case certificate.KeyTypeECDSA:
			req.PrivateKey, err = certificate.GenerateECDSAPrivateKey(req.KeyCurve)
		case certificate.KeyTypeRSA:
			req.PrivateKey, err = certificate.GenerateRSAPrivateKey(req.KeyLength)
		default:
			return fmt.Errorf("Unable to generate certificate request, key type %s is not supported", req.KeyType.String())
		}
		if err != nil {
			return err
		}
		err = certificate.GenerateRequest(req, req.PrivateKey)
		if err != nil {
			return err
		}
		req.CSR = pem.EncodeToMemory(certificate.GetCertificateRequestPEMBlock(req.CSR))

	case certificate.UserProvidedCSR:
		if config.CustomAttributeValues[tppAttributeManualCSR] == "0" {
			return fmt.Errorf("Unable to request certificate with user provided CSR when zone configuration is 'Manual Csr' = 0")
		}
		if req.CSR == nil || len(req.CSR) == 0 {
			return fmt.Errorf("CSR was supposed to be provided by user, but it's empty")
		}

	case certificate.ServiceGeneratedCSR:
		req.CSR = nil
	}
	return nil
}

func getPolicyDN(zone string) string {
	modified := zone
	reg := regexp.MustCompile("^\\\\VED\\\\Policy")
	if reg.FindStringIndex(modified) == nil {
		reg = regexp.MustCompile("^\\\\")
		if reg.FindStringIndex(modified) == nil {
			modified = "\\" + modified
		}
		modified = "\\VED\\Policy" + modified
	}
	return modified
}

func parseAuthorizeResult(httpStatusCode int, httpStatus string, body []byte) (string, error) {
	switch httpStatusCode {
	case http.StatusOK:
		auth, err := parseAuthorizeData(body)
		if err != nil {
			return "", err
		}
		return auth.APIKey, nil
	default:
		return "", fmt.Errorf("Unexpected status code on TPP Authorize. Status: %s", httpStatus)
	}
}

func parseAuthorizeData(b []byte) (authorizeResponse, error) {
	var data authorizeResponse
	err := json.Unmarshal(b, &data)
	if err != nil {
		return data, err
	}

	return data, nil
}

func parseConfigResult(httpStatusCode int, httpStatus string, body []byte) (tppData tppPolicyData, err error) {
	tppData = tppPolicyData{}
	switch httpStatusCode {
	case http.StatusOK:
		tppData, err := parseConfigData(body)
		if err != nil {
			return tppData, err
		}
		return tppData, nil
	default:
		return tppData, fmt.Errorf("Unexpected status code on TPP Config Operation. Status: %s", httpStatus)
	}
}

func parseConfigData(b []byte) (tppPolicyData, error) {
	var data tppPolicyData
	err := json.Unmarshal(b, &data)
	if err != nil {
		return data, err
	}

	return data, nil
}

func parseRequestResult(httpStatusCode int, httpStatus string, body []byte) (string, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		reqData, err := parseRequestData(body)
		if err != nil {
			return "", err
		}
		return reqData.CertificateDN, nil
	default:
		return "", fmt.Errorf("Unexpected status code on TPP Certificate Request. Status: %s. Body: %s", httpStatus, body)
	}
}

func parseRequestData(b []byte) (certificateRequestResponse, error) {
	var data certificateRequestResponse
	err := json.Unmarshal(b, &data)
	if err != nil {
		return data, err
	}

	return data, nil
}

func parseRetrieveResult(httpStatusCode int, httpStatus string, body []byte) (certificateRetrieveResponse, error) {
	var retrieveResponse certificateRetrieveResponse
	switch httpStatusCode {
	case http.StatusOK, http.StatusAccepted:
		retrieveResponse, err := parseRetrieveData(body)
		if err != nil {
			return retrieveResponse, err
		}
		return retrieveResponse, nil
	default:
		return retrieveResponse, fmt.Errorf("Unexpected status code on TPP Certificate Retrieval. Status: %s", httpStatus)
	}
}

func parseRetrieveData(b []byte) (certificateRetrieveResponse, error) {
	var data certificateRetrieveResponse
	err := json.Unmarshal(b, &data)
	if err != nil {
		return data, err
	}
	// fmt.Printf("\n\n%s\n\n%+v\n\n", string(b), data)
	return data, nil
}

func parseRevokeResult(httpStatusCode int, httpStatus string, body []byte) (certificateRevokeResponse, error) {
	var revokeResponse certificateRevokeResponse
	switch httpStatusCode {
	case http.StatusOK, http.StatusAccepted:
		revokeResponse, err := parseRevokeData(body)
		if err != nil {
			return revokeResponse, err
		}
		return revokeResponse, nil
	default:
		return revokeResponse, fmt.Errorf("Unexpected status code on TPP Certificate Revocation. Status: %s", httpStatus)
	}
}

func parseRevokeData(b []byte) (certificateRevokeResponse, error) {
	var data certificateRevokeResponse
	err := json.Unmarshal(b, &data)
	if err != nil {
		return data, err
	}
	return data, nil
}

func parseRenewResult(httpStatusCode int, httpStatus string, body []byte) (resp certificateRenewResponse, err error) {
	resp, err = parseRenewData(body)
	if err != nil {
		return resp, fmt.Errorf("failed to parse certificate renewal response. status: %s", httpStatus)
	}
	return resp, nil
}

func parseRenewData(b []byte) (certificateRenewResponse, error) {
	var data certificateRenewResponse
	err := json.Unmarshal(b, &data)
	return data, err
}

func newPEMCollectionFromResponse(base64Response string, chainOrder certificate.ChainOption) (*certificate.PEMCollection, error) {
	if base64Response != "" {
		certBytes, err := base64.StdEncoding.DecodeString(base64Response)
		if err != nil {
			return nil, err
		}

		return certificate.PEMCollectionFromBytes(certBytes, chainOrder)
	}
	return nil, nil
}
