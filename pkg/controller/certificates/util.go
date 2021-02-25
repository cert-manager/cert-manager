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
	"crypto/rsa"
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

func PrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	spec = *spec.DeepCopy()
	if spec.PrivateKey == nil {
		spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	switch spec.PrivateKey.Algorithm {
	case "", cmapi.RSAKeyAlgorithm:
		return rsaPrivateKeyMatchesSpec(pk, spec)
	case cmapi.ECDSAKeyAlgorithm:
		return ecdsaPrivateKeyMatchesSpec(pk, spec)
	default:
		return nil, fmt.Errorf("unrecognised key algorithm type %q", spec.PrivateKey.Algorithm)
	}
}

func rsaPrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return []string{"spec.keyAlgorithm"}, nil
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
		violations = append(violations, "spec.keySize")
	}
	return violations, nil
}

func ecdsaPrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	ecdsaPk, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return []string{"spec.keyAlgorithm"}, nil
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
		violations = append(violations, "spec.keySize")
	}
	return violations, nil
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

// RenewBeforeExpiryDuration will return the amount of time before the given
// NotAfter time that the certificate should be renewed.
func RenewBeforeExpiryDuration(notBefore, notAfter time.Time, specRenewBefore *metav1.Duration, defaultRenewBeforeExpiryDuration time.Duration) time.Duration {
	renewBefore := defaultRenewBeforeExpiryDuration
	if specRenewBefore != nil {
		renewBefore = specRenewBefore.Duration
	}
	actualDuration := notAfter.Sub(notBefore)
	if renewBefore >= actualDuration {
		renewBefore = actualDuration / 3
	}
	return renewBefore
}
