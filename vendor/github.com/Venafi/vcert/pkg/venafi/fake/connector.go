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

package fake

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"math/big"
	"strings"
	"time"
)

type Connector struct {
	verbose bool
}

func NewConnector(verbose bool, trust *x509.CertPool) *Connector {
	c := Connector{verbose: verbose}
	return &c
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeFake
}

func (c *Connector) SetZone(z string) {
	return
}

func (c *Connector) Ping() (err error) {
	return
}

func (c *Connector) Register(email string) (err error) {
	return
}

func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	return
}

type fakeRequestID struct {
	Req *certificate.Request
	CSR string
}

func validateRequest(req *certificate.Request) error {
	if strings.HasSuffix(req.Subject.CommonName, "venafi.com") {
		return fmt.Errorf("%s certificate cannot be requested", req.Subject.CommonName)
	}
	return nil
}

func (c *Connector) RequestCertificate(req *certificate.Request, zone string) (requestID string, err error) {

	err = validateRequest(req)
	if err != nil {
		return "", fmt.Errorf("certificate request validation fail: %s", err)
	}

	var fakeRequest = fakeRequestID{}

	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR, certificate.UserProvidedCSR:
		// should return CSR as requestID payload
		fakeRequest.CSR = base64.StdEncoding.EncodeToString(req.CSR)

	case certificate.ServiceGeneratedCSR:
		// should return certificate.Request as requestID payload
		fakeRequest.Req = req

	default:
		return "", fmt.Errorf("Unexpected option in PrivateKeyOrigin")
	}

	js, err := json.Marshal(fakeRequest)
	if err != nil {
		return "", fmt.Errorf("failed to json.Marshal(certificate.Request: %v)", req)
	}
	pickupID := base64.StdEncoding.EncodeToString(js)
	req.PickupID = pickupID
	return pickupID, nil
}

func issueCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, limit)

	if "disabled" == "CSR pre-precessing for HTTPS" {
		csr.DNSNames = append(csr.DNSNames, csr.Subject.CommonName)

		nameSet := map[string]bool{}
		for _, name := range csr.DNSNames {
			nameSet[name] = true
		}
		uniqNames := []string{}
		for name, _ := range nameSet {
			uniqNames = append(uniqNames, name)
		}
		csr.DNSNames = uniqNames
	}

	certRequest := x509.Certificate{
		SerialNumber: serial,
	}
	certRequest.Subject = csr.Subject
	certRequest.DNSNames = csr.DNSNames
	certRequest.EmailAddresses = csr.EmailAddresses
	certRequest.IPAddresses = csr.IPAddresses
	certRequest.SignatureAlgorithm = x509.SHA512WithRSA
	certRequest.PublicKeyAlgorithm = csr.PublicKeyAlgorithm
	certRequest.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	certRequest.NotBefore = time.Now().Add(-24 * time.Hour)
	certRequest.NotAfter = certRequest.NotBefore.AddDate(0, 0, 90)
	certRequest.IsCA = false
	certRequest.BasicConstraintsValid = true
	// ku := x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &certRequest, caCrt, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	res := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return res, nil
}

func (c *Connector) RetrieveCertificate(req *certificate.Request) (pcc *certificate.PEMCollection, err error) {

	bytes, err := base64.StdEncoding.DecodeString(req.PickupID)
	if err != nil {
		return nil, fmt.Errorf("Test-mode: could not parse requestID as base64 encoded fakeRequestID structure")
	}

	var fakeRequest = &fakeRequestID{}
	err = json.Unmarshal(bytes, fakeRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to json.Unmarshal(fakeRequestId): %s\n", err)
	}

	var csrPEMbytes []byte
	var pk interface{}

	if fakeRequest.CSR != "" {
		csrPEMbytes, err = base64.StdEncoding.DecodeString(fakeRequest.CSR)

	} else {
		req := fakeRequest.Req

		switch req.KeyType {
		case certificate.KeyTypeECDSA:
			req.PrivateKey, err = certificate.GenerateECDSAPrivateKey(req.KeyCurve)
		case certificate.KeyTypeRSA:
			req.PrivateKey, err = certificate.GenerateRSAPrivateKey(req.KeyLength)
		default:
			return nil, fmt.Errorf("Unable to generate certificate request, key type %s is not supported", req.KeyType.String())
		}
		if err != nil {
			return
		}

		req.DNSNames = append(req.DNSNames, "fake-service-generated."+req.Subject.CommonName)

		err = certificate.GenerateRequest(req, req.PrivateKey)
		if err != nil {
			return
		}
		csrPEMbytes = pem.EncodeToMemory(certificate.GetCertificateRequestPEMBlock(req.CSR))
		pk = req.PrivateKey
	}

	var (
		csrBlock *pem.Block
		csr      *x509.CertificateRequest
	)
	csrBlock, _ = pem.Decode([]byte(csrPEMbytes))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("Test-mode: could not parse requestID as base64 encoded certificate request block")
	}

	csr, err = x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, err
	}

	cert_pem, err := issueCertificate(csr)
	if err != nil {
		return nil, err
	}

	var certBytes []byte
	switch req.ChainOption {
	case certificate.ChainOptionRootFirst:
		certBytes = append([]byte(caCertPEM+"\n"), cert_pem...)
	default:
		certBytes = append(cert_pem, []byte(caCertPEM)...)
	}
	pcc, err = certificate.PEMCollectionFromBytes(certBytes, req.ChainOption)

	// no key password -- no key
	if pk != nil && req.KeyPassword != "" {
		pcc.AddPrivateKey(pk, []byte(req.KeyPassword))
	}
	return
}

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	return fmt.Errorf("revocation is not supported in -test-mode")
}

func (c *Connector) ReadZoneConfiguration(zone string) (config *endpoint.ZoneConfiguration, err error) {
	return endpoint.NewZoneConfiguration(), nil
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(revReq *certificate.RenewalRequest) (requestID string, err error) {
	return "", fmt.Errorf("renew is not supported in -test-mode")
}

func (c *Connector) ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error) {
	return nil, fmt.Errorf("import is not supported in -test-mode")
}
