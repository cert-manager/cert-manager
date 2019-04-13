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
	"github.com/Venafi/vcert/pkg/certificate"
	"regexp"
	"sort"
	"strings"
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
	GetType() ConnectorType
	SetBaseURL(url string) (err error)
	SetZone(z string)
	Ping() (err error)
	Register(email string) (err error)
	Authenticate(auth *Authentication) (err error)
	ReadZoneConfiguration(zone string) (config *ZoneConfiguration, err error)
	GenerateRequest(config *ZoneConfiguration, req *certificate.Request) (err error)
	RequestCertificate(req *certificate.Request, zone string) (requestID string, err error)
	RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error)
	RevokeCertificate(req *certificate.RevocationRequest) error
	RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error)
	ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error)
}

// Authentication provides a data construct for authentication data
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

// ZoneConfiguration provides a common structure for certificate request data provided by the remote endpoint
type ZoneConfiguration struct {
	Organization       string
	OrganizationLocked bool
	OrganizationalUnit []string
	Country            string
	CountryLocked      bool
	Province           string
	ProvinceLocked     bool
	Locality           string
	LocalityLocked     bool

	SubjectCNRegexes []string
	SubjectORegexes  []string
	SubjectOURegexes []string
	SubjectSTRegexes []string
	SubjectLRegexes  []string
	SubjectCRegexes  []string
	SANRegexes       []string

	AllowedKeyConfigurations []AllowedKeyConfiguration
	KeySizeLocked            bool

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

// ValidateCertificateRequest validates the request against the zone configuration
func (z *ZoneConfiguration) ValidateCertificateRequest(request *certificate.Request) error {
	if !isComponentValid(z.SubjectCNRegexes, []string{request.Subject.CommonName}) {
		return fmt.Errorf("The requested CN does not match any of the allowed CN regular expressions")
	}
	if !isComponentValid(z.SubjectORegexes, request.Subject.Organization) {
		return fmt.Errorf("The requested Organization does not match any of the allowed Organization regular expressions")
	}
	if !isComponentValid(z.SubjectOURegexes, request.Subject.OrganizationalUnit) {
		return fmt.Errorf("The requested Organizational Unit does not match any of the allowed Organization Unit regular expressions")
	}
	if !isComponentValid(z.SubjectSTRegexes, request.Subject.Province) {
		return fmt.Errorf("The requested State/Province does not match any of the allowed State/Province regular expressions")
	}
	if !isComponentValid(z.SubjectLRegexes, request.Subject.Locality) {
		return fmt.Errorf("The requested Locality does not match any of the allowed Locality regular expressions")
	}
	if !isComponentValid(z.SubjectCRegexes, request.Subject.Country) {
		return fmt.Errorf("The requested Country does not match any of the allowed Country regular expressions")
	}
	if !isComponentValid(z.SANRegexes, request.DNSNames) {
		return fmt.Errorf("The requested Subject Alternative Name does not match any of the allowed Country regular expressions")
	}

	if z.AllowedKeyConfigurations != nil && len(z.AllowedKeyConfigurations) > 0 {
		match := false
		for _, keyConf := range z.AllowedKeyConfigurations {
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
	if regexes != nil && len(regexes) > 0 && component != nil {
		regexOk := false
		for _, subReg := range regexes {
			matchedAny := false
			reg := regexp.MustCompile(subReg)
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
	return true
}

// UpdateCertificateRequest updates a certificate request based on the zone configurataion retrieved from the remote endpoint
func (z *ZoneConfiguration) UpdateCertificateRequest(request *certificate.Request) {
	if (request.Subject.Organization == nil || len(request.Subject.Organization) == 0) && z.Organization != "" {
		request.Subject.Organization = []string{z.Organization}
	} else {
		if z.OrganizationLocked && !strings.EqualFold(request.Subject.Organization[0], z.Organization) {
			request.Subject.Organization = []string{z.Organization}
		}
	}
	if (request.Subject.OrganizationalUnit == nil || len(request.Subject.OrganizationalUnit) == 0) && z.OrganizationalUnit != nil {
		request.Subject.OrganizationalUnit = z.OrganizationalUnit
	}

	if (request.Subject.Country == nil || len(request.Subject.Country) == 0) && z.Country != "" {
		request.Subject.Country = []string{z.Country}
	} else {
		if z.CountryLocked && !strings.EqualFold(request.Subject.Country[0], z.Country) {
			request.Subject.Country = []string{z.Country}
		}
	}
	if (request.Subject.Province == nil || len(request.Subject.Province) == 0) && z.Province != "" {
		request.Subject.Province = []string{z.Province}
	} else {
		if z.ProvinceLocked && !strings.EqualFold(request.Subject.Province[0], z.Province) {
			request.Subject.Province = []string{z.Province}
		}
	}
	if (request.Subject.Locality == nil || len(request.Subject.Locality) == 0) && z.Locality != "" {
		request.Subject.Locality = []string{z.Locality}
	} else {
		if z.LocalityLocked && !strings.EqualFold(request.Subject.Locality[0], z.Locality) {
			request.Subject.Locality = []string{z.Locality}
		}
	}
	if z.HashAlgorithm != 0 {
		request.SignatureAlgorithm = z.HashAlgorithm
	} else {
		request.SignatureAlgorithm = x509.SHA256WithRSA
	}

	if z.KeySizeLocked {
		for _, keyConf := range z.AllowedKeyConfigurations {
			if keyConf.KeyType == request.KeyType {
				sort.Sort(sort.Reverse(sort.IntSlice(keyConf.KeySizes)))
				request.KeyLength = keyConf.KeySizes[0]
			}
		}
	} else if z.AllowedKeyConfigurations != nil {
		foundMatch := false
		for _, keyConf := range z.AllowedKeyConfigurations {
			if keyConf.KeyType == request.KeyType {
				foundMatch = true
				switch request.KeyType {
				case certificate.KeyTypeECDSA:
					if z.AllowedKeyConfigurations[0].KeyCurves != nil {
						request.KeyCurve = z.AllowedKeyConfigurations[0].KeyCurves[0]
					} else {
						request.KeyCurve = certificate.EllipticCurveP256
					}
				case certificate.KeyTypeRSA:
					if keyConf.KeySizes != nil {
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
			request.KeyType = z.AllowedKeyConfigurations[0].KeyType
			switch request.KeyType {
			case certificate.KeyTypeECDSA:
				if z.AllowedKeyConfigurations[0].KeyCurves != nil {
					request.KeyCurve = z.AllowedKeyConfigurations[0].KeyCurves[0]
				} else {
					request.KeyCurve = certificate.EllipticCurveP256
				}
			case certificate.KeyTypeRSA:
				if z.AllowedKeyConfigurations[0].KeySizes != nil {
					sort.Sort(sort.Reverse(sort.IntSlice(z.AllowedKeyConfigurations[0].KeySizes)))
					request.KeyLength = z.AllowedKeyConfigurations[0].KeySizes[0]
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

	return
}
