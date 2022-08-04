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

package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"

	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// PrivateKeyMatchesSpec returns an error if the private key bit size
// doesn't match the provided spec. RSA, Ed25519 and ECDSA are supported.
// If any error is returned, a list of violations will also be returned.
func PrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	spec = *spec.DeepCopy()
	if spec.PrivateKey == nil {
		spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	switch spec.PrivateKey.Algorithm {
	case "", cmapi.RSAKeyAlgorithm:
		return rsaPrivateKeyMatchesSpec(pk, spec)
	case cmapi.Ed25519KeyAlgorithm:
		return ed25519PrivateKeyMatchesSpec(pk, spec)
	case cmapi.ECDSAKeyAlgorithm:
		return ecdsaPrivateKeyMatchesSpec(pk, spec)
	default:
		return nil, fmt.Errorf("unrecognised key algorithm type %q", spec.PrivateKey.Algorithm)
	}
}

func rsaPrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return []string{"spec.privateKey.algorithm"}, nil
	}
	var violations []string
	// TODO: we should not use implicit defaulting here, and instead rely on
	//  defaulting performed within the Kubernetes apiserver here.
	//  This requires careful handling in order to not interrupt users upgrading
	//  from older versions.
	// The default RSA keySize is set to 2048.
	keySize := pki.MinRSAKeySize
	if spec.PrivateKey.Size > 0 {
		keySize = spec.PrivateKey.Size
	}
	if rsaPk.N.BitLen() != keySize {
		violations = append(violations, "spec.privateKey.size")
	}
	return violations, nil
}

func ecdsaPrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	ecdsaPk, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return []string{"spec.privateKey.algorithm"}, nil
	}
	var violations []string
	// TODO: we should not use implicit defaulting here, and instead rely on
	//  defaulting performed within the Kubernetes apiserver here.
	//  This requires careful handling in order to not interrupt users upgrading
	//  from older versions.
	// The default EC curve type is EC256
	expectedKeySize := pki.ECCurve256
	if spec.PrivateKey.Size > 0 {
		expectedKeySize = spec.PrivateKey.Size
	}
	if expectedKeySize != ecdsaPk.Curve.Params().BitSize {
		violations = append(violations, "spec.privateKey.size")
	}
	return violations, nil
}

func ed25519PrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	_, ok := pk.(ed25519.PrivateKey)
	if !ok {
		return []string{"spec.privateKey.algorithm"}, nil
	}

	return nil, nil
}

// RequestMatchesSpec compares a CertificateRequest with a CertificateSpec
// and returns a list of field names on the Certificate that do not match their
// counterpart fields on the CertificateRequest.
// If decoding the x509 certificate request fails, an error will be returned.
func RequestMatchesSpec(req *cmapi.CertificateRequest, spec cmapi.CertificateSpec) ([]string, error) {
	x509req, err := pki.DecodeX509CertificateRequestBytes(req.Spec.Request)
	if err != nil {
		return nil, err
	}

	// It is safe to mutate top-level fields in `spec` as it is not a pointer
	// meaning changes will not effect the caller.
	if spec.Subject == nil {
		spec.Subject = &cmapi.X509Subject{}
	}

	var violations []string
	if spec.LiteralSubject == "" {
		if x509req.Subject.CommonName != spec.CommonName {
			violations = append(violations, "spec.commonName")
		}
		if !util.EqualUnsorted(x509req.DNSNames, spec.DNSNames) {
			violations = append(violations, "spec.dnsNames")
		}
		if !util.EqualUnsorted(pki.IPAddressesToString(x509req.IPAddresses), spec.IPAddresses) {
			violations = append(violations, "spec.ipAddresses")
		}
		if !util.EqualUnsorted(pki.URLsToString(x509req.URIs), spec.URIs) {
			violations = append(violations, "spec.uris")
		}
		if !util.EqualUnsorted(x509req.EmailAddresses, spec.EmailAddresses) {
			violations = append(violations, "spec.emailAddresses")
		}
		if x509req.Subject.SerialNumber != spec.Subject.SerialNumber {
			violations = append(violations, "spec.subject.serialNumber")
		}
		if !util.EqualUnsorted(x509req.Subject.Organization, spec.Subject.Organizations) {
			violations = append(violations, "spec.subject.organizations")
		}
		if !util.EqualUnsorted(x509req.Subject.Country, spec.Subject.Countries) {
			violations = append(violations, "spec.subject.countries")
		}
		if !util.EqualUnsorted(x509req.Subject.Locality, spec.Subject.Localities) {
			violations = append(violations, "spec.subject.localities")
		}
		if !util.EqualUnsorted(x509req.Subject.OrganizationalUnit, spec.Subject.OrganizationalUnits) {
			violations = append(violations, "spec.subject.organizationalUnits")
		}
		if !util.EqualUnsorted(x509req.Subject.PostalCode, spec.Subject.PostalCodes) {
			violations = append(violations, "spec.subject.postCodes")
		}
		if !util.EqualUnsorted(x509req.Subject.Province, spec.Subject.Provinces) {
			violations = append(violations, "spec.subject.postCodes")
		}
		if !util.EqualUnsorted(x509req.Subject.StreetAddress, spec.Subject.StreetAddresses) {
			violations = append(violations, "spec.subject.streetAddresses")
		}
		if req.Spec.IsCA != spec.IsCA {
			violations = append(violations, "spec.isCA")
		}
		if !util.EqualKeyUsagesUnsorted(req.Spec.Usages, spec.Usages) {
			violations = append(violations, "spec.usages")
		}
		if spec.Duration != nil && req.Spec.Duration != nil &&
			spec.Duration.Duration != req.Spec.Duration.Duration {
			violations = append(violations, "spec.duration")
		}
		if !reflect.DeepEqual(spec.IssuerRef, req.Spec.IssuerRef) {
			violations = append(violations, "spec.issuerRef")
		}
	} else {
		// we have a LiteralSubject
		// parse the subject of the csr in the same way as we parse LiteralSubject and see whether the RDN Sequences match

		var rdnSequenceFromCertificateRequest pkix.RDNSequence
		_, err2 := asn1.Unmarshal(x509req.RawSubject, &rdnSequenceFromCertificateRequest)
		if err2 != nil {
			return nil, err2
		}

		rdnSequenceFromCertificate, err := pki.ParseSubjectStringToRdnSequence(spec.LiteralSubject)
		if err != nil {
			return nil, err
		}

		if !reflect.DeepEqual(rdnSequenceFromCertificate, rdnSequenceFromCertificateRequest) {
			violations = append(violations, "spec.literalSubject")
		}
	}

	return violations, nil
}

// SecretDataAltNamesMatchSpec will compare a Secret resource containing certificate
// data to a CertificateSpec and return a list of 'violations' for any fields that
// do not match their counterparts.
// This is a purposely less comprehensive check than RequestMatchesSpec as some
// issuers override/force certain fields.
func SecretDataAltNamesMatchSpec(secret *corev1.Secret, spec cmapi.CertificateSpec) ([]string, error) {
	x509cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}

	var violations []string

	// Perform a 'loose' check on the x509 certificate to determine if the
	// commonName and dnsNames fields are up to date.
	// This check allows names to move between the DNSNames and CommonName
	// field freely in order to account for CAs behaviour of promoting DNSNames
	// to be CommonNames or vice-versa.
	expectedDNSNames := sets.NewString(spec.DNSNames...)
	if spec.CommonName != "" {
		expectedDNSNames.Insert(spec.CommonName)
	}
	allDNSNames := sets.NewString(x509cert.DNSNames...)
	if x509cert.Subject.CommonName != "" {
		allDNSNames.Insert(x509cert.Subject.CommonName)
	}
	if !allDNSNames.Equal(expectedDNSNames) {
		// We know a mismatch occurred, so now determine which fields mismatched.
		if (spec.CommonName != "" && !allDNSNames.Has(spec.CommonName)) || (x509cert.Subject.CommonName != "" && !expectedDNSNames.Has(x509cert.Subject.CommonName)) {
			violations = append(violations, "spec.commonName")
		}

		if !allDNSNames.HasAll(spec.DNSNames...) || !expectedDNSNames.HasAll(x509cert.DNSNames...) {
			violations = append(violations, "spec.dnsNames")
		}
	}

	if !util.EqualUnsorted(pki.IPAddressesToString(x509cert.IPAddresses), spec.IPAddresses) {
		violations = append(violations, "spec.ipAddresses")
	}
	if !util.EqualUnsorted(pki.URLsToString(x509cert.URIs), spec.URIs) {
		violations = append(violations, "spec.uris")
	}
	if !util.EqualUnsorted(x509cert.EmailAddresses, spec.EmailAddresses) {
		violations = append(violations, "spec.emailAddresses")
	}

	return violations, nil
}

// staticTemporarySerialNumber is a fixed serial number we use for temporary certificates
const staticTemporarySerialNumber = "1234567890"

// GenerateLocallySignedTemporaryCertificate signs a temporary certificate for
// the given certificate resource using a one-use temporary CA that is then
// discarded afterwards.
// This is to mitigate a potential attack against x509 certificates that use a
// predictable serial number and weak MD5 hashing algorithms.
// In practice, this shouldn't really be a concern anyway.
func GenerateLocallySignedTemporaryCertificate(crt *cmapi.Certificate, pkData []byte) ([]byte, error) {
	// generate a throwaway self-signed root CA
	caPk, err := pki.GenerateECPrivateKey(pki.ECCurve521)
	if err != nil {
		return nil, err
	}
	caCertTemplate, err := pki.GenerateTemplate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
			CommonName: "cert-manager.local",
			IsCA:       true,
		},
	})
	if err != nil {
		return nil, err
	}
	_, caCert, err := pki.SignCertificate(caCertTemplate, caCertTemplate, caPk.Public(), caPk)
	if err != nil {
		return nil, err
	}

	// sign a temporary certificate using the root CA
	template, err := pki.GenerateTemplate(crt)
	if err != nil {
		return nil, err
	}
	template.Subject.SerialNumber = staticTemporarySerialNumber

	signeeKey, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		return nil, err
	}

	b, _, err := pki.SignCertificate(template, caCert, signeeKey.Public(), caPk)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// RenewalTimeFunc is a custom function type for calculating renewal time of a certificate.
type RenewalTimeFunc func(time.Time, time.Time, *metav1.Duration) *metav1.Time

// RenewalTime calculates renewal time for a certificate. Default renewal time
// is 2/3 through certificate's lifetime. If user has configured
// spec.renewBefore, renewal time will be renewBefore period before expiry
// (unless that is after the expiry).
func RenewalTime(notBefore, notAfter time.Time, renewBeforeOverride *metav1.Duration) *metav1.Time {

	// 1. Calculate how long before expiry a cert should be renewed

	actualDuration := notAfter.Sub(notBefore)

	renewBefore := actualDuration / 3

	// If spec.renewBefore was set (and is less than duration)
	// respect that. We don't want to prevent users from renewing
	// longer lived certs more frequently.
	if renewBeforeOverride != nil && renewBeforeOverride.Duration < actualDuration {
		renewBefore = renewBeforeOverride.Duration
	}

	// 2. Calculate when a cert should be renewed

	// Truncate the renewal time to nearest second. This is important
	// because the renewal time also gets stored on Certificate's status
	// where it is truncated to the nearest second. We use the renewal time
	// from Certificate's status to determine when the Certificate will be
	// added to the queue to be renewed, but then re-calculate whether it
	// needs to be renewed _now_ using this function- so returning a
	// non-truncated value here would potentially cause Certificates to be
	// re-queued for renewal earlier than the calculated renewal time thus
	// causing Certificates to not be automatically renewed. See
	// https://github.com/cert-manager/cert-manager/pull/4399.
	rt := metav1.NewTime(notAfter.Add(-1 * renewBefore).Truncate(time.Second))
	return &rt
}
