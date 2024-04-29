/*
Copyright 2020 The cert-manager Authors.

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

package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
)

type CertificateTemplateValidatorMutator func(*x509.CertificateRequest, *x509.Certificate) error

func hasExtension(checkReq *x509.CertificateRequest, extensionID asn1.ObjectIdentifier) bool {
	for _, ext := range checkReq.Extensions {
		if ext.Id.Equal(extensionID) {
			return true
		}
	}

	for _, ext := range checkReq.ExtraExtensions {
		if ext.Id.Equal(extensionID) {
			return true
		}
	}

	return false
}

// CertificateTemplateOverrideDuration returns a CertificateTemplateValidatorMutator that overrides the
// certificate duration.
func CertificateTemplateOverrideDuration(duration time.Duration) CertificateTemplateValidatorMutator {
	return func(req *x509.CertificateRequest, cert *x509.Certificate) error {
		cert.NotBefore = time.Now()
		cert.NotAfter = cert.NotBefore.Add(duration)
		return nil
	}
}

// CertificateTemplateValidateAndOverrideBasicConstraints returns a CertificateTemplateValidatorMutator that overrides
// the certificate basic constraints.
func CertificateTemplateValidateAndOverrideBasicConstraints(isCA bool, maxPathLen *int) CertificateTemplateValidatorMutator {
	return func(req *x509.CertificateRequest, cert *x509.Certificate) error {
		if hasExtension(req, OIDExtensionBasicConstraints) {
			if !cert.BasicConstraintsValid {
				return fmt.Errorf("encoded CSR error: BasicConstraintsValid is not true")
			}

			if cert.IsCA != isCA {
				return fmt.Errorf("encoded CSR error: IsCA %v does not match expected value %v", cert.IsCA, isCA)
			}

			// We explicitly do not check the MaxPathLen and MaxPathLenZero fields here, as there is no way to
			// configure these fields in a CertificateRequest or CSR object yet. If we ever add a way to configure
			// these fields, we should add a check here to ensure that the values match the expected values.
			// The provided maxPathLen is only used to override the value, not to validate it.
			// TODO: if we add support for maxPathLen, we should add a check here to ensure that the value in the
			// CertificateRequest or CSR matches the value encoded in the CSR blob.
		}

		cert.BasicConstraintsValid = true
		cert.IsCA = isCA
		if maxPathLen != nil {
			cert.MaxPathLen = *maxPathLen
			cert.MaxPathLenZero = *maxPathLen == 0
		} else {
			cert.MaxPathLen = 0
			cert.MaxPathLenZero = false
		}
		return nil
	}
}

// CertificateTemplateValidateAndOverrideKeyUsages returns a CertificateTemplateValidatorMutator that overrides the
// certificate key usages.
func CertificateTemplateValidateAndOverrideKeyUsages(keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) CertificateTemplateValidatorMutator {
	return func(req *x509.CertificateRequest, cert *x509.Certificate) error {
		if hasExtension(req, OIDExtensionKeyUsage) || hasExtension(req, OIDExtensionExtendedKeyUsage) {
			if cert.KeyUsage != keyUsage {
				return fmt.Errorf("encoded CSR error: the KeyUsages %s do not match the expected KeyUsages %s",
					printKeyUsage(apiutil.KeyUsageStrings(cert.KeyUsage)),
					printKeyUsage(apiutil.KeyUsageStrings(keyUsage)),
				)
			}

			if !slices.Equal(cert.ExtKeyUsage, extKeyUsage) {
				return fmt.Errorf("encoded CSR error: the ExtKeyUsages %s do not match the expected ExtKeyUsages %s",
					printKeyUsage(apiutil.ExtKeyUsageStrings(cert.ExtKeyUsage)),
					printKeyUsage(apiutil.ExtKeyUsageStrings(extKeyUsage)),
				)
			}
		}

		cert.KeyUsage = keyUsage
		cert.ExtKeyUsage = extKeyUsage
		return nil
	}
}

type printKeyUsage []v1.KeyUsage

func (k printKeyUsage) String() string {
	var sb strings.Builder
	sb.WriteString("[")
	for i, u := range k {
		sb.WriteString(" '")
		sb.WriteString(string(u))
		sb.WriteString("'")
		if i < len(k)-1 {
			sb.WriteString(",")
		}
	}
	if len(k) > 0 {
		sb.WriteString(" ")
	}
	sb.WriteString("]")
	return sb.String()
}

// CertificateTemplateFromCSR will create a x509.Certificate for the
// given *x509.CertificateRequest.
func CertificateTemplateFromCSR(csr *x509.CertificateRequest, validatorMutators ...CertificateTemplateValidatorMutator) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err.Error())
	}

	cert := &x509.Certificate{
		// Version must be 3 according to RFC5280.
		// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1
		Version:            3,
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		Subject:            csr.Subject,
		RawSubject:         csr.RawSubject,

		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}

	// Start by copying all extensions from the CSR
	extractExtensions := func(template *x509.Certificate, val pkix.Extension) error {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(OIDExtensionBasicConstraints) {
			unmarshalIsCA, unmarshalMaxPathLen, err := UnmarshalBasicConstraints(val.Value)
			if err != nil {
				return err
			}

			template.BasicConstraintsValid = true
			template.IsCA = unmarshalIsCA
			if unmarshalMaxPathLen != nil {
				template.MaxPathLen = *unmarshalMaxPathLen
				template.MaxPathLenZero = *unmarshalMaxPathLen == 0
			} else {
				template.MaxPathLen = 0
				template.MaxPathLenZero = false
			}
		}

		if val.Id.Equal(OIDExtensionNameConstraints) {
			nameConstraints, err := UnmarshalNameConstraints(val.Value)
			if err != nil {
				return err
			}
			template.PermittedDNSDomainsCritical = val.Critical
			template.PermittedDNSDomains = nameConstraints.PermittedDNSDomains
			template.PermittedIPRanges = nameConstraints.PermittedIPRanges
			template.PermittedEmailAddresses = nameConstraints.PermittedEmailAddresses
			template.PermittedURIDomains = nameConstraints.PermittedURIDomains
			template.ExcludedDNSDomains = nameConstraints.ExcludedDNSDomains
			template.ExcludedIPRanges = nameConstraints.ExcludedIPRanges
			template.ExcludedEmailAddresses = nameConstraints.ExcludedEmailAddresses
			template.ExcludedURIDomains = nameConstraints.ExcludedURIDomains
		}

		// RFC 5280, 4.2.1.3
		if val.Id.Equal(OIDExtensionKeyUsage) {
			usage, err := UnmarshalKeyUsage(val.Value)
			if err != nil {
				return err
			}

			template.KeyUsage = usage
		}

		if val.Id.Equal(OIDExtensionExtendedKeyUsage) {
			extUsages, unknownUsages, err := UnmarshalExtKeyUsage(val.Value)
			if err != nil {
				return err
			}

			template.ExtKeyUsage = extUsages
			template.UnknownExtKeyUsage = unknownUsages
		}

		// The SANs fields in the Certificate resource are not enough to
		// represent the full set of SANs that can be encoded in a CSR.
		// Therefore, we need to copy the SANs from the CSR into the
		// ExtraExtensions field of the certificate template.
		if val.Id.Equal(oidExtensionSubjectAltName) {
			template.ExtraExtensions = append(template.ExtraExtensions, val)
		}

		return nil
	}

	for _, val := range csr.Extensions {
		if err := extractExtensions(cert, val); err != nil {
			return nil, err
		}
	}

	for _, val := range csr.ExtraExtensions {
		if err := extractExtensions(cert, val); err != nil {
			return nil, err
		}
	}

	cert.Extensions = csr.Extensions

	for _, validatorMutator := range validatorMutators {
		if err := validatorMutator(csr, cert); err != nil {
			return nil, err
		}
	}

	// Finally, we fix up the certificate template to ensure that it is valid
	{
		// If the certificate has an empty Subject, we set any SAN extensions to be critical
		var asn1Subject []byte
		if cert.RawSubject != nil {
			asn1Subject = cert.RawSubject
		} else {
			asn1Subject, err = asn1.Marshal(cert.Subject.ToRDNSequence())
			if err != nil {
				return nil, fmt.Errorf("failed to marshal subject to ASN.1 DER: %s", err.Error())
			}
		}

		for i := range cert.ExtraExtensions {
			if cert.ExtraExtensions[i].Id.Equal(oidExtensionSubjectAltName) {
				cert.ExtraExtensions[i].Critical = IsASN1SubjectEmpty(asn1Subject)
			}
		}
	}

	return cert, nil
}

// CertificateTemplateFromCSRPEM will create a x509.Certificate for the
// given csrPEM.
func CertificateTemplateFromCSRPEM(csrPEM []byte, validatorMutators ...CertificateTemplateValidatorMutator) (*x509.Certificate, error) {
	csr, err := DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	return CertificateTemplateFromCSR(csr, validatorMutators...)
}

// CertificateTemplateFromCertificate will create a x509.Certificate for the given
// Certificate resource
func CertificateTemplateFromCertificate(crt *v1.Certificate) (*x509.Certificate, error) {
	csr, err := GenerateCSR(crt)
	if err != nil {
		return nil, err
	}

	certDuration := apiutil.DefaultCertDuration(crt.Spec.Duration)
	keyUsage, extKeyUsage, err := KeyUsagesForCertificateOrCertificateRequest(crt.Spec.Usages, crt.Spec.IsCA)
	if err != nil {
		return nil, err
	}

	return CertificateTemplateFromCSR(
		csr,
		CertificateTemplateOverrideDuration(certDuration),
		CertificateTemplateValidateAndOverrideBasicConstraints(crt.Spec.IsCA, nil),
		CertificateTemplateValidateAndOverrideKeyUsages(keyUsage, extKeyUsage),
	)
}

// CertificateTemplateFromCertificateRequest will create a x509.Certificate for the given
// CertificateRequest resource
func CertificateTemplateFromCertificateRequest(cr *v1.CertificateRequest) (*x509.Certificate, error) {
	certDuration := apiutil.DefaultCertDuration(cr.Spec.Duration)
	keyUsage, extKeyUsage, err := KeyUsagesForCertificateOrCertificateRequest(cr.Spec.Usages, cr.Spec.IsCA)
	if err != nil {
		return nil, err
	}

	return CertificateTemplateFromCSRPEM(
		cr.Spec.Request,
		CertificateTemplateOverrideDuration(certDuration),
		CertificateTemplateValidateAndOverrideBasicConstraints(cr.Spec.IsCA, nil), // Override the basic constraints, but make sure they match the constraints in the CSR if present
		CertificateTemplateValidateAndOverrideKeyUsages(keyUsage, extKeyUsage),    // Override the key usages, but make sure they match the usages in the CSR if present
	)
}

// CertificateTemplateFromCertificateSigningRequest will create a x509.Certificate for the given
// CertificateSigningRequest resource
func CertificateTemplateFromCertificateSigningRequest(csr *certificatesv1.CertificateSigningRequest) (*x509.Certificate, error) {
	duration, err := DurationFromCertificateSigningRequest(csr)
	if err != nil {
		return nil, err
	}

	ku, eku, err := BuildKeyUsagesKube(csr.Spec.Usages)
	if err != nil {
		return nil, err
	}

	isCA := csr.Annotations[experimentalapi.CertificateSigningRequestIsCAAnnotationKey] == "true"

	return CertificateTemplateFromCSRPEM(
		csr.Spec.Request,
		CertificateTemplateOverrideDuration(duration),
		CertificateTemplateValidateAndOverrideBasicConstraints(isCA, nil), // Override the basic constraints, but make sure they match the constraints in the CSR if present
		CertificateTemplateValidateAndOverrideKeyUsages(ku, eku),          // Override the key usages, but make sure they match the usages in the CSR if present
	)
}
