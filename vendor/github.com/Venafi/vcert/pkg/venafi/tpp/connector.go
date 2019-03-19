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
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Connector contains the base data needed to communicate with a TPP Server
type Connector struct {
	baseURL string
	apiKey  string
	verbose bool
	trust   *x509.CertPool
	zone    string
}

// NewConnector creates a new TPP Connector object used to communicate with TPP
func NewConnector(verbose bool, trust *x509.CertPool) *Connector {
	c := Connector{trust: trust, verbose: verbose}
	return &c
}

func (c *Connector) SetZone(z string) {
	c.zone = z
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeTPP
}

//Ping attempts to connect to the TPP Server WebSDK API and returns an errror if it cannot
func (c *Connector) Ping() (err error) {
	url, err := c.getURL("")
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(req)
	if err != nil {
		return err
	} else if res.StatusCode != http.StatusOK {
		defer res.Body.Close()
		body, _ := ioutil.ReadAll(res.Body)
		err = fmt.Errorf("%s", string(body))
	}
	return err
}

//Register does nothing for TPP
func (c *Connector) Register(email string) (err error) {
	return nil
}

// Authenticate authenticates the user to the TPP
func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}
	url, err := c.getURL(urlResourceAuthorize)
	if err != nil {
		return err
	}

	b, _ := json.Marshal(authorizeResquest{Username: auth.User, Password: auth.Password})
	payload := bytes.NewReader(b)
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(req)
	if err == nil {
		defer res.Body.Close()
		body, _ := ioutil.ReadAll(res.Body)

		key, err := parseAuthorizeResult(res.StatusCode, res.Status, body)
		if err != nil {
			if c.verbose {
				log.Printf("JSON sent for %s\n%s", urlResourceAuthorize, strings.Replace(fmt.Sprintf("%s", b), auth.Password, "********", -1))
			}
			return err
		}
		c.apiKey = key
		return nil
	}
	return err
}

func wrapAltNames(req *certificate.Request) (items []sanItem) {
	for _, name := range req.EmailAddresses {
		items = append(items, sanItem{1, name})
	}
	for _, name := range req.DNSNames {
		items = append(items, sanItem{2, name})
	}
	for _, name := range req.IPAddresses {
		items = append(items, sanItem{7, name.String()})
	}
	return items
}

func wrapKeyType(kt certificate.KeyType) string {
	switch kt {
	case certificate.KeyTypeRSA:
		return "RSA"
	case certificate.KeyTypeECDSA:
		return "ECC"
	default:
		return kt.String()
	}
}

func prepareRequest(req *certificate.Request, zone string) (tppReq certificateRequest, err error) {
	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR, certificate.UserProvidedCSR:
		tppReq = certificateRequest{
			PolicyDN:                getPolicyDN(zone),
			PKCS10:                  string(req.CSR),
			ObjectName:              req.FriendlyName,
			DisableAutomaticRenewal: true}

	case certificate.ServiceGeneratedCSR:
		tppReq = certificateRequest{
			PolicyDN:                getPolicyDN(zone),
			ObjectName:              req.FriendlyName,
			Subject:                 req.Subject.CommonName, // TODO: there is some problem because Subject is not only CN
			SubjectAltNames:         wrapAltNames(req),
			DisableAutomaticRenewal: true}

	default:
		return tppReq, fmt.Errorf("Unexpected option in PrivateKeyOrigin")
	}

	switch req.KeyType {
	case certificate.KeyTypeRSA:
		tppReq.KeyAlgorithm = "RSA"
		tppReq.KeyBitSize = req.KeyLength
	case certificate.KeyTypeECDSA:
		tppReq.KeyAlgorithm = "ECC"
		tppReq.EllipticCurve = req.KeyCurve.String()
	}

	return tppReq, err
}

// RequestCertificate submits the CSR to TPP returning the DN of the requested Certificate
func (c *Connector) RequestCertificate(req *certificate.Request, zone string) (requestID string, err error) {

	if zone == "" {
		zone = c.zone
	}

	tppCertificateRequest, err := prepareRequest(req, zone)
	if err != nil {
		return "", err
	}

	b, _ := json.Marshal(tppCertificateRequest)

	url, err := c.getURL(urlResourceCertificateRequest)
	if err != nil {
		return "", err
	}
	payload := bytes.NewReader(b)
	request, _ := http.NewRequest("POST", url, payload)
	request.Header.Add("x-venafi-api-key", c.apiKey)
	request.Header.Add("content-type", "application/json")
	request.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(request)

	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	requestID, err = parseRequestResult(res.StatusCode, res.Status, body)
	if err != nil {
		if c.verbose {
			log.Printf("JSON sent for %s\n%s", urlResourceCertificateRequest, b)
		}
		return "", fmt.Errorf("%s: %s", err, string(body))
	}
	req.PickupID = requestID
	return requestID, nil
}

// RetrieveCertificate attempts to retrieve the requested certificate
func (c *Connector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {

	includeChain := req.ChainOption != certificate.ChainOptionIgnore
	rootFirstOrder := includeChain && req.ChainOption == certificate.ChainOptionRootFirst

	if req.PickupID == "" && req.Thumbprint != "" {
		// search cert by Thumbprint and fill pickupID
		searchResult, err := c.searchCertificatesByFingerprint(req.Thumbprint)
		if err != nil {
			return nil, fmt.Errorf("Failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return nil, fmt.Errorf("No certifiate found using fingerprint %s", req.Thumbprint)
		}
		if len(searchResult.Certificates) > 1 {
			return nil, fmt.Errorf("Error: more than one CertificateRequestId was found with the same thumbprint")
		}
		req.PickupID = searchResult.Certificates[0].CertificateRequestId
	}

	certReq := certificateRetrieveRequest{
		CertificateDN:  req.PickupID,
		Format:         "base64",
		RootFirstOrder: rootFirstOrder,
		IncludeChain:   includeChain,
	}
	if req.CsrOrigin == certificate.ServiceGeneratedCSR || req.FetchPrivateKey {
		certReq.IncludePrivateKey = true
		certReq.Password = req.KeyPassword
	}

	startTime := time.Now()
	for {
		retrieveResponse, err := c.retrieveCertificateOnce(certReq)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve: %s", err)
		}
		if retrieveResponse.CertificateData != "" {
			return newPEMCollectionFromResponse(retrieveResponse.CertificateData, req.ChainOption)
		}
		if req.Timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: retrieveResponse.Status}
		}
		if time.Now().After(startTime.Add(req.Timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
		}
		time.Sleep(2 * time.Second)
	}
}

func (c *Connector) retrieveCertificateOnce(certReq certificateRetrieveRequest) (*certificateRetrieveResponse, error) {
	url, err := c.getURL(urlResourceCertificateRetrieve)
	if err != nil {
		return nil, err
	}

	b, _ := json.Marshal(certReq)

	payload := bytes.NewReader(b)
	r, _ := http.NewRequest("POST", url, payload)
	r.Header.Add("x-venafi-api-key", c.apiKey)
	r.Header.Add("content-type", "application/json")
	r.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(r)

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	retrieveResponse, err := parseRetrieveResult(res.StatusCode, res.Status, body)
	if err != nil {
		if c.verbose {
			log.Printf("JSON sent for %s\n%s", urlResourceCertificateRetrieve, b)
		}
		return nil, err
	}
	return &retrieveResponse, nil
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(renewReq *certificate.RenewalRequest) (requestID string, err error) {

	if renewReq.Thumbprint != "" && renewReq.CertificateDN == "" {
		// search by Thumbprint and fill *renewReq.CertificateDN
		searchResult, err := c.searchCertificatesByFingerprint(renewReq.Thumbprint)
		if err != nil {
			return "", fmt.Errorf("Failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return "", fmt.Errorf("No certifiate found using fingerprint %s", renewReq.Thumbprint)
		}
		if len(searchResult.Certificates) > 1 {
			return "", fmt.Errorf("Error: more than one CertificateRequestId was found with the same thumbprint")
		}

		renewReq.CertificateDN = searchResult.Certificates[0].CertificateRequestId
	}
	if renewReq.CertificateDN == "" {
		return "", fmt.Errorf("failed to create renewal request: CertificateDN or Thumbprint required")
	}

	url, err := c.getURL(urlResourceCertificateRenew)
	if err != nil {
		return "", err
	}

	var r = certificateRenewRequest{}
	r.CertificateDN = renewReq.CertificateDN
	if renewReq.CertificateRequest != nil && len(renewReq.CertificateRequest.CSR) > 0 {
		r.PKCS10 = string(renewReq.CertificateRequest.CSR)
	}

	b, _ := json.Marshal(r)
	payload := bytes.NewReader(b)
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("x-venafi-api-key", c.apiKey)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(req)

	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	response, err := parseRenewResult(res.StatusCode, res.Status, body)
	if err != nil {
		if c.verbose {
			log.Printf("JSON sent for %s\n%s", url, b)
			log.Printf("Response: %s", string(body))
		}
		return "", err
	}
	if !response.Success {
		return "", fmt.Errorf("Certificate Renewal error: %s", response.Error)
	}
	return renewReq.CertificateDN, nil
}

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	url, err := c.getURL(urlResourceCertificateRevoke)
	if err != nil {
		return err
	}

	reason, ok := RevocationReasonsMap[revReq.Reason]
	if !ok {
		return fmt.Errorf("could not parse revocation reason `%s`", revReq.Reason)
	}

	var r = certificateRevokeRequest{
		revReq.CertificateDN,
		revReq.Thumbprint,
		reason,
		revReq.Comments,
		revReq.Disable,
	}

	b, _ := json.Marshal(r)
	payload := bytes.NewReader(b)
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("x-venafi-api-key", c.apiKey)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(req)

	if err != nil {
		return err
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	revokeResponse, err := parseRevokeResult(res.StatusCode, res.Status, body)
	if err != nil {
		if c.verbose {
			log.Printf("JSON sent for %s\n%s", urlResourceCertificateRevoke, b)
		}
		return err
	}
	if !revokeResponse.Success {
		return fmt.Errorf("Revocation error: %s", revokeResponse.Error)
	}
	return
}

//ReadZoneConfiguration reads the policy data from TPP to get locked and pre-configured values for certificate requests
func (c *Connector) ReadZoneConfiguration(zone string) (config *endpoint.ZoneConfiguration, err error) {
	zoneConfig := endpoint.NewZoneConfiguration()
	zoneConfig.HashAlgorithm = x509.SHA256WithRSA
	policyDN := getPolicyDN(zone)
	keyType := certificate.KeyTypeRSA

	url, err := c.getURL(urlResourceFindPolicy)
	if err != nil {
		return nil, err
	}
	attributes := []string{tppAttributeOrg, tppAttributeOrgUnit, tppAttributeCountry, tppAttributeState, tppAttributeLocality, tppAttributeKeyAlgorithm, tppAttributeKeySize, tppAttributeEllipticCurve, tppAttributeRequestHash, tppAttributeManagementType, tppAttributeManualCSR}
	for _, attrib := range attributes {
		b, _ := json.Marshal(policyRequest{ObjectDN: policyDN, Class: "X509 Certificate", AttributeName: attrib})
		payload := bytes.NewReader(b)
		req, _ := http.NewRequest("POST", url, payload)
		req.Header.Add("x-venafi-api-key", c.apiKey)
		req.Header.Add("content-type", "application/json")
		req.Header.Add("cache-control", "no-cache")

		res, err := c.getHTTPClient().Do(req)

		if err == nil {
			defer res.Body.Close()
			body, _ := ioutil.ReadAll(res.Body)

			tppData, err := parseConfigResult(res.StatusCode, res.Status, body)
			if tppData.Error == "" && (err != nil || tppData.Values == nil || len(tppData.Values) == 0) {
				continue
			} else if tppData.Error != "" && tppData.Result == 400 { //object does not exist
				return nil, fmt.Errorf(tppData.Error)
			}

			switch attrib {
			case tppAttributeOrg:
				zoneConfig.Organization = tppData.Values[0]
				zoneConfig.OrganizationLocked = tppData.Locked
			case tppAttributeOrgUnit:
				zoneConfig.OrganizationalUnit = tppData.Values
			case tppAttributeCountry:
				zoneConfig.Country = tppData.Values[0]
				zoneConfig.CountryLocked = tppData.Locked
			case tppAttributeState:
				zoneConfig.Province = tppData.Values[0]
				zoneConfig.ProvinceLocked = tppData.Locked
			case tppAttributeLocality:
				zoneConfig.Locality = tppData.Values[0]
				zoneConfig.LocalityLocked = tppData.Locked
			case tppAttributeKeyAlgorithm:
				err = keyType.Set(tppData.Values[0])
				if err == nil {
					zoneConfig.AllowedKeyConfigurations = []endpoint.AllowedKeyConfiguration{endpoint.AllowedKeyConfiguration{KeyType: keyType}}
				}
			case tppAttributeKeySize:
				temp, err := strconv.Atoi(tppData.Values[0])
				if err == nil {
					zoneConfig.AllowedKeyConfigurations = []endpoint.AllowedKeyConfiguration{endpoint.AllowedKeyConfiguration{KeyType: keyType, KeySizes: []int{temp}}}
					zoneConfig.KeySizeLocked = tppData.Locked
				}
			case tppAttributeEllipticCurve:
				curve := certificate.EllipticCurveP256
				err = curve.Set(tppData.Values[0])
				if err == nil {
					zoneConfig.AllowedKeyConfigurations = []endpoint.AllowedKeyConfiguration{endpoint.AllowedKeyConfiguration{KeyType: certificate.KeyTypeECDSA, KeyCurves: []certificate.EllipticCurve{curve}}}
					zoneConfig.KeySizeLocked = tppData.Locked
				}
			case tppAttributeRequestHash:
				alg, err := strconv.Atoi(tppData.Values[0])
				if err == nil {
					switch alg {
					case pkcs10HashAlgorithmSha1:
						zoneConfig.HashAlgorithm = x509.SHA1WithRSA
					case pkcs10HashAlgorithmSha384:
						zoneConfig.HashAlgorithm = x509.SHA384WithRSA
					case pkcs10HashAlgorithmSha512:
						zoneConfig.HashAlgorithm = x509.SHA512WithRSA
					default:
						zoneConfig.HashAlgorithm = x509.SHA256WithRSA
					}
				}
			case tppAttributeManagementType, tppAttributeManualCSR:
				if tppData.Locked {
					zoneConfig.CustomAttributeValues[attrib] = tppData.Values[0]
				}
			}
		} else {
			if c.verbose {
				log.Printf("JSON sent for %s\n%s", urlResourceFindPolicy, b)
			}
			return nil, err
		}
	}

	return zoneConfig, nil
}

func (c *Connector) ImportCertificate(r *certificate.ImportRequest) (*certificate.ImportResponse, error) {
	url, err := c.getURL(urlResourceCertificateImport)
	if err != nil {
		return nil, err
	}

	if r.PolicyDN == "" {
		r.PolicyDN = getPolicyDN(c.zone)
	}

	b, _ := json.Marshal(r)
	payload := bytes.NewReader(b)
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("x-venafi-api-key", c.apiKey)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	switch res.StatusCode {
	case http.StatusOK:

		var response = &certificate.ImportResponse{}
		err := json.Unmarshal(body, response)
		if err != nil {
			return nil, fmt.Errorf("failed to decode import response message: %s", err)
		}
		return response, nil

	case http.StatusBadRequest:
		var errorResponse = &struct{ Error string }{}
		err := json.Unmarshal(body, errorResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to decode error message: %s", err)
		}
		return nil, fmt.Errorf("%s", errorResponse.Error)
	default:
		return nil, fmt.Errorf("unexpected response status %d: %s", res.StatusCode, string(b))
	}
}
