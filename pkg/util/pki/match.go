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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
)

// PrivateKeyMatchesSpec returns a list of violations for the provided private
// key against the provided CertificateSpec. It will return an empty list/ nil
// if there are no violations found. RSA, Ed25519 and ECDSA private keys are
// supported.
// The function panics if the CertificateSpec contains an unknown key algorithm,
// since this should have been caught by the CertificateSpec validation already.
func PrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) []string {
	spec = *spec.DeepCopy()
	if spec.PrivateKey == nil {
		spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	switch spec.PrivateKey.Algorithm {
	case "", cmapi.RSAKeyAlgorithm:
		return rsaPrivateKeyMatchesSpec(pk, spec)
	case cmapi.Ed25519KeyAlgorithm:
		return ed25519PrivateKeyMatchesSpec(pk)
	case cmapi.ECDSAKeyAlgorithm:
		return ecdsaPrivateKeyMatchesSpec(pk, spec)
	default:
		// This should never happen as the CertificateSpec validation should
		// catch this before it reaches this point.
		panic(fmt.Sprintf("[PROGRAMMING ERROR] unrecognised key algorithm type %q", spec.PrivateKey.Algorithm))
	}
}

func rsaPrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) []string {
	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return []string{"spec.privateKey.algorithm"}
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
	return violations
}

func ecdsaPrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) []string {
	ecdsaPk, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return []string{"spec.privateKey.algorithm"}
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
	return violations
}

func ed25519PrivateKeyMatchesSpec(pk crypto.PrivateKey) []string {
	_, ok := pk.(ed25519.PrivateKey)
	if !ok {
		return []string{"spec.privateKey.algorithm"}
	}

	return nil
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
	// meaning changes will not affect the caller.
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
		// we have a LiteralSubject, generate the RDNSequence and encode it to compare
		// with the request's subject

		rdnSequenceFromCertificate, err := UnmarshalSubjectStringToRDNSequence(spec.LiteralSubject)
		if err != nil {
			return nil, err
		}

		asn1Sequence, err := asn1.Marshal(rdnSequenceFromCertificate)
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(x509req.RawSubject, asn1Sequence) {
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
	// RequestMatchesSpec compares the IssuerRef in the CertificateRequest and
	// CertificateSpec, regardless of any differences which are solely due to
	// the presence or absence of default group (cert-manager.io) and kind (Issuer).
	//
	// We do not want to re-issue the Certificate if the user explicitly adds
	// the default issuer group and kind.
	// Nor do we want to re-issue if the user removes the default issuer group and kind.
	//
	// And we want to avoid re-issuing if a future version of the cert-manager
	// CRDs introduces API defaults for issuerRef group and kind. Specifically,
	// we want to gracefully handle a situation where the platform admin
	// upgrades the CRDs to a version that has defaults, but not the controller.
	// In that situation, when the CRDs are upgraded, the controller
	// re-establishes its watches and refreshes its caches with updated Certificates
	// and CertificateRequests, containing the new API defaults. But this
	// doesn't happen transactionally, so the updated Certificates may start
	// being reconciled before the cached CertificateRequests have been updated
	// and there will be a mis-match if the Certificate has the default
	// group/kind set but the CertificateRequest does not.
	if req.Spec.IssuerRef.Name != spec.IssuerRef.Name ||
		!issuerKindsEqual(req.Spec.IssuerRef.Kind, spec.IssuerRef.Kind) ||
		!issuerGroupsEqual(req.Spec.IssuerRef.Group, spec.IssuerRef.Group) {
		violations = append(violations, "spec.issuerRef")
	}

	// TODO: check spec.EncodeBasicConstraintsInRequest and spec.EncodeUsagesInRequest

	return violations, nil
}

// These defaults are also applied at runtime by the cert-manager
// CertificateRequest controller.
const (
	// defaultIssuerKind is the default value for an IssuerRef's kind field
	// if it is not specified.
	defaultIssuerKind = cmapi.IssuerKind
	// defaultIssuerGroup is the default value for an IssuerRef's group field
	// if it is not specified.
	defaultIssuerGroup = certmanager.GroupName
)

// issuerKindsEqual returns true if the two issuer reference kinds are equal,
// taking into account the defaulting of the kind to "Issuer".
func issuerKindsEqual(l, r string) bool {
	if l == "" {
		l = defaultIssuerKind
	}
	if r == "" {
		r = defaultIssuerKind
	}
	return l == r
}

// issuerGroupsEqual returns true if the two issuer reference groups are equal,
// taking into account defaulting of the group to "cert-manager.io".
func issuerGroupsEqual(l, r string) bool {
	if l == "" {
		l = defaultIssuerGroup
	}
	if r == "" {
		r = defaultIssuerGroup
	}
	return l == r
}

func matchOtherNames(extension []pkix.Extension, specOtherNames []cmapi.OtherName) (bool, error) {
	x509SANExtension, err := extractSANExtension(extension)
	if err != nil {
		return false, nil //nolint:nilerr
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

// FuzzyX509AltNamesMatchSpec will compare a X509 Certificate to a CertificateSpec
// and return a list of 'violations' for any fields that do not match their counterparts.
//
// This is a purposely less comprehensive check than RequestMatchesSpec as some
// issuers override/force certain fields.
//
// Deprecated: This function is very fuzzy and makes too many assumptions about
// how the issuer maps a CSR to a certificate. We only keep it for backward compatibility
// reasons, but use other comparison functions when possible.
func FuzzyX509AltNamesMatchSpec(x509cert *x509.Certificate, spec cmapi.CertificateSpec) []string {
	var violations []string

	// Perform a 'loose' check on the x509 certificate to determine if the
	// commonName and dnsNames fields are up to date.
	// This check allows names to move between the DNSNames and CommonName
	// field freely in order to account for CAs behaviour of promoting DNSNames
	// to be CommonNames or vice-versa.
	expectedDNSNames := sets.New(spec.DNSNames...)
	if spec.CommonName != "" {
		expectedDNSNames.Insert(spec.CommonName)
	}
	allDNSNames := sets.New(x509cert.DNSNames...)
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

	return violations
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
