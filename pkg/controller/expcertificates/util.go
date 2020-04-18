/*
Copyright 2020 The Jetstack cert-manager contributors.

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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func PrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	switch spec.KeyAlgorithm {
	case "", cmapi.RSAKeyAlgorithm:
		return rsaPrivateKeyMatchesSpec(pk, spec)
	case cmapi.ECDSAKeyAlgorithm:
		return ecdsaPrivateKeyMatchesSpec(pk, spec)
	default:
		return nil, fmt.Errorf("unrecognised key algorithm type %q", spec.KeyAlgorithm)
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
	if spec.KeySize > 0 {
		keySize = spec.KeySize
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
	if spec.KeySize > 0 {
		expectedKeySize = spec.KeySize
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
	x509req, err := pki.DecodeX509CertificateRequestBytes(req.Spec.CSRPEM)
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
	if !util.EqualUnsorted(pki.URLsToString(x509req.URIs), spec.URISANs) {
		violations = append(violations, "spec.uriSANs")
	}
	if x509req.Subject.SerialNumber != spec.Subject.SerialNumber {
		violations = append(violations, "spec.subject.serialNumber")
	}
	if !util.EqualUnsorted(x509req.Subject.Organization, spec.Organization) {
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
	if !util.EqualUnsorted(pki.URLsToString(x509cert.URIs), spec.URISANs) {
		violations = append(violations, "spec.uriSANs")
	}
	if !util.EqualUnsorted(x509cert.EmailAddresses, spec.EmailSANs) {
		violations = append(violations, "spec.emailSANs")
	}

	return violations, nil
}
