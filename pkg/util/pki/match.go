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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"

	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
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
	keySize := MinRSAKeySize
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
	expectedKeySize := ECCurve256
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

func ipSlicesMatch(parsedIPs []net.IP, stringIPs []string) bool {
	parsedStringIPs := make([]net.IP, len(stringIPs))

	for i, s := range stringIPs {
		parsedStringIPs[i] = net.ParseIP(s)
	}

	return util.EqualIPsUnsorted(parsedStringIPs, parsedIPs)
}

// RequestMatchesSpec compares a CertificateRequest with a CertificateSpec
// and returns a list of field names on the Certificate that do not match their
// counterpart fields on the CertificateRequest.
// If decoding the x509 certificate request fails, an error will be returned.
func RequestMatchesSpec(req *cmapi.CertificateRequest, spec cmapi.CertificateSpec) ([]string, error) {
	x509req, err := DecodeX509CertificateRequestBytes(req.Spec.Request)
	if err != nil {
		return nil, err
	}

	// It is safe to mutate top-level fields in `spec` as it is not a pointer
	// meaning changes will not effect the caller.
	if spec.Subject == nil {
		spec.Subject = &cmapi.X509Subject{}
	}

	var violations []string

	if !ipSlicesMatch(x509req.IPAddresses, spec.IPAddresses) {
		violations = append(violations, "spec.ipAddresses")
	}

	if !util.EqualUnsorted(URLsToString(x509req.URIs), spec.URIs) {
		violations = append(violations, "spec.uris")
	}

	if !util.EqualUnsorted(x509req.EmailAddresses, spec.EmailAddresses) {
		violations = append(violations, "spec.emailAddresses")
	}

	if !util.EqualUnsorted(x509req.DNSNames, spec.DNSNames) {
		violations = append(violations, "spec.dnsNames")
	}

	if spec.OtherNames != nil {
		matched, err := matchOtherNames(x509req.Extensions, spec.OtherNames)
		if err != nil {
			return nil, err
		}
		if !matched {
			violations = append(violations, "spec.otherNames")
		}
	}

	if spec.LiteralSubject == "" {
		// Comparing Subject fields
		if x509req.Subject.CommonName != spec.CommonName {
			violations = append(violations, "spec.commonName")
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

	} else {
		// we have a LiteralSubject
		// parse the subject of the csr in the same way as we parse LiteralSubject and see whether the RDN Sequences match

		rdnSequenceFromCertificateRequest, err := UnmarshalRawDerBytesToRDNSequence(x509req.RawSubject)
		if err != nil {
			return nil, err
		}

		rdnSequenceFromCertificate, err := UnmarshalSubjectStringToRDNSequence(spec.LiteralSubject)
		if err != nil {
			return nil, err
		}

		if !reflect.DeepEqual(rdnSequenceFromCertificate, rdnSequenceFromCertificateRequest) {
			violations = append(violations, "spec.literalSubject")
		}
	}

	if req.Spec.IsCA != spec.IsCA {
		violations = append(violations, "spec.isCA")
	}
	if !util.EqualKeyUsagesUnsorted(req.Spec.Usages, spec.Usages) {
		violations = append(violations, "spec.usages")
	}
	if req.Spec.Duration != nil && spec.Duration != nil &&
		req.Spec.Duration.Duration != spec.Duration.Duration {
		violations = append(violations, "spec.duration")
	}
	if !reflect.DeepEqual(req.Spec.IssuerRef, spec.IssuerRef) {
		violations = append(violations, "spec.issuerRef")
	}

	// TODO: check spec.EncodeBasicConstraintsInRequest and spec.EncodeUsagesInRequest

	return violations, nil
}

func matchOtherNames(extension []pkix.Extension, specOtherNames []cmapi.OtherName) (bool, error) {
	x509SANExtension, err := extractSANExtension(extension)
	if err != nil {
		return false, nil
	}

	x509GeneralNames, err := UnmarshalSANs(x509SANExtension.Value)
	if err != nil {
		return false, err
	}

	x509OtherNames := make([]cmapi.OtherName, 0, len(x509GeneralNames.OtherNames))
	for _, otherName := range x509GeneralNames.OtherNames {

		var otherNameInnerValue asn1.RawValue
		// We have to perform one more level of unwrapping because value is still context specific class
		// tagged 0
		_, err := asn1.Unmarshal(otherName.Value.Bytes, &otherNameInnerValue)
		if err != nil {
			return false, err
		}

		uv, err := UnmarshalUniversalValue(otherNameInnerValue)
		if err != nil {
			return false, err
		}

		if uv.Type() != UniversalValueTypeUTF8String {
			// This means the CertificateRequest's otherName was not an utf8 value
			return false, fmt.Errorf("otherName is not an utf8 value, got: %v", uv.Type())
		}

		x509OtherNames = append(x509OtherNames, cmapi.OtherName{
			OID:       otherName.TypeID.String(),
			UTF8Value: uv.UTF8String,
		})
	}

	if !util.EqualOtherNamesUnsorted(x509OtherNames, specOtherNames) {
		return false, nil
	}

	return true, nil
}

// SecretDataAltNamesMatchSpec will compare a Secret resource containing certificate
// data to a CertificateSpec and return a list of 'violations' for any fields that
// do not match their counterparts.
// This is a purposely less comprehensive check than RequestMatchesSpec as some
// issuers override/force certain fields.
func SecretDataAltNamesMatchSpec(secret *corev1.Secret, spec cmapi.CertificateSpec) ([]string, error) {
	x509cert, err := DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}

	var violations []string

	// Perform a 'loose' check on the x509 certificate to determine if the
	// commonName and dnsNames fields are up to date.
	// This check allows names to move between the DNSNames and CommonName
	// field freely in order to account for CAs behaviour of promoting DNSNames
	// to be CommonNames or vice-versa.
	expectedDNSNames := sets.New[string](spec.DNSNames...)
	if spec.CommonName != "" {
		expectedDNSNames.Insert(spec.CommonName)
	}
	allDNSNames := sets.New[string](x509cert.DNSNames...)
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

	if !ipSlicesMatch(x509cert.IPAddresses, spec.IPAddresses) {
		violations = append(violations, "spec.ipAddresses")
	}

	if !util.EqualUnsorted(URLsToString(x509cert.URIs), spec.URIs) {
		violations = append(violations, "spec.uris")
	}

	if !util.EqualUnsorted(x509cert.EmailAddresses, spec.EmailAddresses) {
		violations = append(violations, "spec.emailAddresses")
	}

	return violations, nil
}

func extractSANExtension(extensions []pkix.Extension) (pkix.Extension, error) {
	oidExtensionSubjectAltName := []int{2, 5, 29, 17}

	for _, extension := range extensions {
		if extension.Id.Equal(oidExtensionSubjectAltName) {
			return extension, nil
		}
	}

	return pkix.Extension{}, fmt.Errorf("SAN extension not present!")
}
