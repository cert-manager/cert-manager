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

package endpoint

import (
	"crypto/x509"
	"fmt"
	"log"
	"regexp"
	"sort"

	"github.com/Venafi/vcert/pkg/certificate"
)

// ConnectorType represents the available connectors
type ConnectorType int

const (
	ConnectorTypeUndefined ConnectorType = iota
	// ConnectorTypeFake is a fake connector for tests
	ConnectorTypeFake
	// ConnectorTypeCloud represents the Cloud connector type
	ConnectorTypeCloud
	// ConnectorTypeTPP represents the TPP connector type
	ConnectorTypeTPP
)

func (t ConnectorType) String() string {
	switch t {
	case ConnectorTypeUndefined:
		return "Undefined Endpoint"
	case ConnectorTypeFake:
		return "Fake Endpoint"
	case ConnectorTypeCloud:
		return "Venafi Cloud"
	case ConnectorTypeTPP:
		return "TPP"
	default:
		return fmt.Sprintf("unexpected connector type: %d", t)
	}
}

// Connector provides a common interface for external communications with TPP or Venafi Cloud
type Connector interface {
	// GetType returns a connector type (cloud/TPP/fake). Can be useful because some features are not supported by a Cloud connection.
	GetType() ConnectorType
	// SetZone sets a zone (by name) for requests with this connector.
	SetZone(z string)
	Ping() (err error)
	// Authenticate is usually called by NewClient and it is not required that you manually call it.
	Authenticate(auth *Authentication) (err error)
	// ReadPolicyConfiguration returns information about zone policies. It can be used for checking request compatibility with policies.
	ReadPolicyConfiguration() (policy *Policy, err error)
	// ReadZoneConfiguration returns the zone configuration. A zone configuration includes zone policy and additional zone information.
	ReadZoneConfiguration() (config *ZoneConfiguration, err error)
	// GenerateRequest update certificate.Request with data from zone configuration.
	GenerateRequest(config *ZoneConfiguration, req *certificate.Request) (err error)
	// RequestCertificate makes a request to the server with data for enrolling the certificate.
	RequestCertificate(req *certificate.Request) (requestID string, err error)
	// RetrieveCertificate immediately returns an enrolled certificate. Otherwise, RetrieveCertificate waits and retries during req.Timeout.
	RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error)
	RevokeCertificate(req *certificate.RevocationRequest) error
	RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error)
	// ImportCertificate adds an existing certificate to Venafi Platform even if the certificate was not issued by Venafi Cloud or Venafi Platform. For information purposes.
	ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error)
}

// Authentication provides a struct for authentication data. Either specify User and Password for Trust Platform or specify an APIKey for Cloud.
type Authentication struct {
	User     string
	Password string
	APIKey   string
}

// ErrRetrieveCertificateTimeout provides a common error structure for a timeout while retrieving a certificate
type ErrRetrieveCertificateTimeout struct {
	CertificateID string
}

func (err ErrRetrieveCertificateTimeout) Error() string {
	return fmt.Sprintf("Operation timed out. You may try retrieving the certificate later using Pickup ID: %s", err.CertificateID)
}

// ErrCertificatePending provides a common error structure for a timeout while retrieving a certificate
type ErrCertificatePending struct {
	CertificateID string
	Status        string
}

func (err ErrCertificatePending) Error() string {
	if err.Status == "" {
		return fmt.Sprintf("Issuance is pending. You may try retrieving the certificate later using Pickup ID: %s", err.CertificateID)
	}
	return fmt.Sprintf("Issuance is pending. You may try retrieving the certificate later using Pickup ID: %s\n\tStatus: %s", err.CertificateID, err.Status)
}

// Policy is struct that contains restrictions for certificates. Most of the fields contains list of regular expression.
// For satisfying policies, all values in the certificate field must match AT LEAST ONE regular expression in corresponding policy field.
type Policy struct {
	SubjectCNRegexes []string
	SubjectORegexes  []string
	SubjectOURegexes []string
	SubjectSTRegexes []string
	SubjectLRegexes  []string
	SubjectCRegexes  []string
	// AllowedKeyConfigurations lists all allowed key configurations. Certificate key configuration have to be listed in this list.
	// For example: If key has type RSA and length 2048 bit for satisfying the policy, that list must contain AT LEAST ONE configuration with type RSA and value 2048 in KeySizes list of this configuration.
	AllowedKeyConfigurations []AllowedKeyConfiguration
	// DnsSanRegExs is a list of regular expressions that show allowable DNS names in SANs.
	DnsSanRegExs []string
	// IpSanRegExs is a list of regular expressions that show allowable DNS names in SANs.
	IpSanRegExs    []string
	EmailSanRegExs []string
	UriSanRegExs   []string
	UpnSanRegExs   []string
	AllowWildcards bool
	AllowKeyReuse  bool
}

// ZoneConfiguration provides a common structure for certificate request data provided by the remote endpoint
type ZoneConfiguration struct {
	Organization       string
	OrganizationalUnit []string
	Country            string
	Province           string
	Locality           string
	Policy

	HashAlgorithm x509.SignatureAlgorithm

	CustomAttributeValues map[string]string
}

// AllowedKeyConfiguration contains an allowed key type with its sizes or curves
type AllowedKeyConfiguration struct {
	KeyType   certificate.KeyType
	KeySizes  []int
	KeyCurves []certificate.EllipticCurve
}

// NewZoneConfiguration creates a new zone configuration which creates the map used in the configuration
func NewZoneConfiguration() *ZoneConfiguration {
	zc := ZoneConfiguration{}
	zc.CustomAttributeValues = make(map[string]string)

	return &zc
}

// ValidateCertificateRequest validates the request against the Policy
func (p *Policy) ValidateCertificateRequest(request *certificate.Request) error {
	if !isComponentValid(p.SubjectCNRegexes, []string{request.Subject.CommonName}) {
		return fmt.Errorf("The requested CN does not match any of the allowed CN regular expressions")
	}
	if !isComponentValid(p.SubjectORegexes, request.Subject.Organization) {
		return fmt.Errorf("The requested Organization does not match any of the allowed Organization regular expressions")
	}
	if !isComponentValid(p.SubjectOURegexes, request.Subject.OrganizationalUnit) {
		return fmt.Errorf("The requested Organizational Unit does not match any of the allowed Organization Unit regular expressions")
	}
	if !isComponentValid(p.SubjectSTRegexes, request.Subject.Province) {
		return fmt.Errorf("The requested State/Province does not match any of the allowed State/Province regular expressions")
	}
	if !isComponentValid(p.SubjectLRegexes, request.Subject.Locality) {
		return fmt.Errorf("The requested Locality does not match any of the allowed Locality regular expressions")
	}
	if !isComponentValid(p.SubjectCRegexes, request.Subject.Country) {
		return fmt.Errorf("The requested Country does not match any of the allowed Country regular expressions")
	}
	if !isComponentValid(p.DnsSanRegExs, request.DNSNames) {
		return fmt.Errorf("The requested Subject Alternative Name does not match any of the allowed Country regular expressions")
	}
	//todo: add ip, email and over cheking

	if p.AllowedKeyConfigurations != nil && len(p.AllowedKeyConfigurations) > 0 {
		match := false
		for _, keyConf := range p.AllowedKeyConfigurations {
			if keyConf.KeyType == request.KeyType {
				if request.KeyLength > 0 {
					for _, size := range keyConf.KeySizes {
						if size == request.KeyLength {
							match = true
							break
						}
					}
				} else {
					match = true
				}
			}
			if match {
				break
			}
		}
		if !match {
			return fmt.Errorf("The requested Key Type and Size do not match any of the allowed Key Types and Sizes")
		}
	}

	return nil
}

func isComponentValid(regexes []string, component []string) bool {
	if len(regexes) == 0 || len(component) == 0 {
		return true
	}
	regexOk := false
	for _, subReg := range regexes {
		matchedAny := false
		reg, err := regexp.Compile(subReg)
		if err != nil {
			log.Printf("Bad regexp: %s", subReg)
			return false
		}
		for _, c := range component {
			if reg.FindStringIndex(c) != nil {
				matchedAny = true
				break
			}
		}
		if matchedAny {
			regexOk = true
			break
		}
	}
	return regexOk
}

// UpdateCertificateRequest updates a certificate request based on the zone configuration retrieved from the remote endpoint
func (z *ZoneConfiguration) UpdateCertificateRequest(request *certificate.Request) {
	if len(request.Subject.Organization) == 0 && z.Organization != "" {
		request.Subject.Organization = []string{z.Organization}
	}

	if len(request.Subject.OrganizationalUnit) == 0 && z.OrganizationalUnit != nil {
		request.Subject.OrganizationalUnit = z.OrganizationalUnit
	}

	if len(request.Subject.Country) == 0 && z.Country != "" {
		request.Subject.Country = []string{z.Country}
	}

	if len(request.Subject.Province) == 0 && z.Province != "" {
		request.Subject.Province = []string{z.Province}
	}

	if len(request.Subject.Locality) == 0 && z.Locality != "" {
		request.Subject.Locality = []string{z.Locality}
	}

	if z.HashAlgorithm != x509.UnknownSignatureAlgorithm {
		request.SignatureAlgorithm = z.HashAlgorithm
	} else {
		request.SignatureAlgorithm = x509.SHA256WithRSA
	}

	if len(z.AllowedKeyConfigurations) != 0 {
		foundMatch := false
		for _, keyConf := range z.AllowedKeyConfigurations {
			if keyConf.KeyType == request.KeyType {
				foundMatch = true
				switch request.KeyType {
				case certificate.KeyTypeECDSA:
					if len(keyConf.KeyCurves) != 0 {
						request.KeyCurve = keyConf.KeyCurves[0]
					} else {
						request.KeyCurve = certificate.EllipticCurveDefault
					}
				case certificate.KeyTypeRSA:
					if len(keyConf.KeySizes) != 0 {
						sizeOK := false
						for _, size := range keyConf.KeySizes {
							if size == request.KeyLength {
								sizeOK = true
							}
						}
						if !sizeOK {
							sort.Sort(sort.Reverse(sort.IntSlice(keyConf.KeySizes)))
							request.KeyLength = keyConf.KeySizes[0]
						}
					} else {
						request.KeyLength = 2048
					}
				}
			}
		}
		if !foundMatch {
			configuration := z.AllowedKeyConfigurations[0]
			request.KeyType = configuration.KeyType
			switch request.KeyType {
			case certificate.KeyTypeECDSA:
				if len(configuration.KeyCurves) != 0 {
					request.KeyCurve = configuration.KeyCurves[0]
				} else {
					request.KeyCurve = certificate.EllipticCurveDefault
				}
			case certificate.KeyTypeRSA:
				if len(configuration.KeySizes) != 0 {
					sort.Sort(sort.Reverse(sort.IntSlice(configuration.KeySizes)))
					request.KeyLength = configuration.KeySizes[0]
				} else {
					request.KeyLength = 2048
				}
			}
		}
	} else {
		// Zone config has no key length parameters, so we just pass user's -key-size or fall to default 2048
		if request.KeyType == certificate.KeyTypeRSA && request.KeyLength == 0 {
			request.KeyLength = 2048
		}
	}
}
