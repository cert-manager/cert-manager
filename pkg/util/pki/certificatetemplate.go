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
	"fmt"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	certificatesv1 "k8s.io/api/certificates/v1"
)

type CertificateTemplateMutator func(*x509.Certificate)

// CertificateTemplateOverrideDuration returns a CertificateTemplateMutator that overrides the
// certificate duration.
func CertificateTemplateOverrideDuration(duration time.Duration) CertificateTemplateMutator {
	return func(cert *x509.Certificate) {
		cert.NotBefore = time.Now()
		cert.NotAfter = cert.NotBefore.Add(duration)
	}
}

// CertificateTemplateOverrideBasicConstraints returns a CertificateTemplateMutator that overrides
// the certificate basic constraints.
func CertificateTemplateOverrideBasicConstraints(isCA bool, maxPathLen *int) CertificateTemplateMutator {
	return func(cert *x509.Certificate) {
		cert.BasicConstraintsValid = true
		cert.IsCA = isCA
		if maxPathLen != nil {
			cert.MaxPathLen = *maxPathLen
			cert.MaxPathLenZero = *maxPathLen == 0
		} else {
			cert.MaxPathLen = 0
			cert.MaxPathLenZero = false
		}
	}
}

// OverrideTemplateKeyUsages returns a CertificateTemplateMutator that overrides the
// certificate key usages.
func CertificateTemplateOverrideKeyUsages(keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) CertificateTemplateMutator {
	return func(cert *x509.Certificate) {
		cert.KeyUsage = keyUsage
		cert.ExtKeyUsage = extKeyUsage
	}
}

// CertificateTemplateAddKeyUsages returns a CertificateTemplateMutator that adds the given key usages
// to the certificate key usages.
func CertificateTemplateAddKeyUsages(keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) CertificateTemplateMutator {
	return func(cert *x509.Certificate) {
		cert.KeyUsage |= keyUsage

	OuterLoop:
		for _, usage := range extKeyUsage {
			for _, existingUsage := range cert.ExtKeyUsage {
				if existingUsage == usage {
					continue OuterLoop
				}
			}

			cert.ExtKeyUsage = append(cert.ExtKeyUsage, usage)
		}
	}
}

// CertificateTemplateFromCSR will create a x509.Certificate for the
// given *x509.CertificateRequest.
// Call OverrideTemplateFromOptions to override the duration, isCA, maxPathLen, keyUsage, and extKeyUsage.
func CertificateTemplateFromCSR(csr *x509.CertificateRequest, mutators ...CertificateTemplateMutator) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err.Error())
	}

	cert := &x509.Certificate{
		// Version must be 2 according to RFC5280.
		// A version value of 2 confusingly means version 3.
		// This value isn't used by Go at the time of writing.
		// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1
		Version:            2,
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		Subject:            csr.Subject,
		RawSubject:         csr.RawSubject,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		EmailAddresses:     csr.EmailAddresses,
		URIs:               csr.URIs,
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

	for _, mutator := range mutators {
		mutator(cert)
	}

	return cert, nil
}

// CertificateTemplateFromCSRPEM will create a x509.Certificate for the
// given csrPEM.
// Call OverrideTemplateFromOptions to override the duration, isCA, maxPathLen, keyUsage, and extKeyUsage.
func CertificateTemplateFromCSRPEM(csrPEM []byte, mutators ...CertificateTemplateMutator) (*x509.Certificate, error) {
	csr, err := DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	return CertificateTemplateFromCSR(csr, mutators...)
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
		CertificateTemplateOverrideBasicConstraints(crt.Spec.IsCA, nil),
		CertificateTemplateOverrideKeyUsages(keyUsage, extKeyUsage),
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
		CertificateTemplateOverrideBasicConstraints(cr.Spec.IsCA, nil),
		CertificateTemplateOverrideKeyUsages(keyUsage, extKeyUsage),
	)
}

// CertificateTemplateFromCertificateRequest will create a x509.Certificate for the given
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
		CertificateTemplateOverrideBasicConstraints(isCA, nil),
		CertificateTemplateOverrideKeyUsages(ku, eku),
	)
}

// Deprecated: use CertificateTemplateFromCertificate instead.
func GenerateTemplate(crt *v1.Certificate) (*x509.Certificate, error) {
	return CertificateTemplateFromCertificate(crt)
}

// Deprecated: use CertificateTemplateFromCertificateRequest instead.
func GenerateTemplateFromCertificateRequest(cr *v1.CertificateRequest) (*x509.Certificate, error) {
	return CertificateTemplateFromCertificateRequest(cr)
}

// Deprecated: use CertificateTemplateFromCertificateSigningRequest instead.
func GenerateTemplateFromCertificateSigningRequest(csr *certificatesv1.CertificateSigningRequest) (*x509.Certificate, error) {
	return CertificateTemplateFromCertificateSigningRequest(csr)
}

// Deprecated: use CertificateTemplateFromCSRPEM instead.
func GenerateTemplateFromCSRPEM(csrPEM []byte, duration time.Duration, isCA bool) (*x509.Certificate, error) {
	return CertificateTemplateFromCSRPEM(
		csrPEM,
		CertificateTemplateOverrideDuration(duration),
		CertificateTemplateOverrideBasicConstraints(isCA, nil),
		CertificateTemplateOverrideKeyUsages(0, nil),
	)
}

// Deprecated: use CertificateTemplateFromCSRPEM instead.
func GenerateTemplateFromCSRPEMWithUsages(csrPEM []byte, duration time.Duration, isCA bool, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) (*x509.Certificate, error) {
	return CertificateTemplateFromCSRPEM(
		csrPEM,
		CertificateTemplateOverrideDuration(duration),
		CertificateTemplateOverrideBasicConstraints(isCA, nil),
		CertificateTemplateOverrideKeyUsages(keyUsage, extKeyUsage),
	)
}
