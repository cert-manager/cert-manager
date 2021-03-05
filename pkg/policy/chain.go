/*
Copyright 2021 The cert-manager Authors.

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

package policy

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"

	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmpolicy "github.com/jetstack/cert-manager/pkg/apis/policy/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/policy/checks"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
)

var (
	parseKeyError = errors.New("failed to parse public key")
)

// check holds the json path to this field, the policy enforced on the field,
// and the requested value.
type check struct {
	path    string
	policy  interface{}
	request interface{}
}

// EvaluateCertificateRequest evaluates whether the given CertificateRequest
// passes the CertificateRequestPolicy. If this request is denied by this
// policy, 'el' will be populated. An error signals that the policy couldn't be
// evaluated to completion.
func EvaluateCertificateRequest(el *field.ErrorList, policy *cmpolicy.CertificateRequestPolicy, cr *cmapi.CertificateRequest) error {
	path := field.NewPath("spec")

	// decode CSR from CertificateRequest
	csr, err := utilpki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return err
	}

	// Add x509 subject and private key checks.
	subjchecks := evaluatex509Subject(el, path.Child("allowedSubject"), policy.Spec.AllowedSubject, csr.Subject)
	pkchecks, err := evaluatePrivateKey(el, path.Child("allowedPrivateKey"), policy.Spec.AllowedPrivateKey, csr)
	if err != nil {
		return err
	}

	// Adds checks for all fields in CertificateRequestPolicy spec
	spec := append(subjchecks, []check{
		{"allowedCommonName", policy.Spec.AllowedCommonName, csr.Subject.CommonName},
		{"allowedMinDuration", policy.Spec.MinDuration, cr.Spec.Duration},
		{"allowedMaxDuration", policy.Spec.MaxDuration, cr.Spec.Duration},
		{"allowedDNSNames", policy.Spec.AllowedDNSNames, csr.DNSNames},
		{"allowedIPAddresses", policy.Spec.AllowedIPAddresses, csr.IPAddresses},
		{"allowedURIs", policy.Spec.AllowedURIs, csr.URIs},
		{"allowedEmailAddresses", policy.Spec.AllowedEmailAddresses, csr.EmailAddresses},
		{"allowedIssuers", policy.Spec.AllowedIssuers, cr.Spec.IssuerRef},
		{"allowedIsCA", policy.Spec.AllowedIsCA, cr.Spec.IsCA},
		{"allowedKeyUsages", policy.Spec.AllowedUsages, cr.Spec.Usages},
	}...)
	spec = append(spec, pkchecks...)

	checks.MinDuration(el, path, policy.Spec.MinDuration, cr.Spec.Duration)
	checks.MaxDuration(el, path, policy.Spec.MinDuration, cr.Spec.Duration)

	// Use the type of the policy and request value to infer which check to
	// perform.
	for _, check := range spec {
		switch check.policy.(type) {

		case *[]string:
			policy := check.policy.(*[]string)
			switch check.request.(type) {
			case string:
				checks.Strings(el, path.Child(check.path), policy, check.request.(string))
			case []string:
				checks.StringSlice(el, path.Child(check.path), policy, check.request.([]string))
			case []net.IP:
				checks.IPSlice(el, path.Child(check.path), policy, check.request.([]net.IP))
			case []*url.URL:
				checks.URLSlice(el, path.Child(check.path), policy, check.request.([]*url.URL))
			}

		case *string:
			checks.String(el, path.Child(check.path), check.policy.(*string), check.request.(string))

		case *[]cmmeta.ObjectReference:
			checks.ObjectReference(el, path.Child(check.path), check.policy.(*[]cmmeta.ObjectReference), check.request.(cmmeta.ObjectReference))

		case *[]cmapi.KeyUsage:
			checks.KeyUsageSlice(el, path.Child(check.path), check.policy.(*[]cmapi.KeyUsage), check.request.([]cmapi.KeyUsage))
		case *[]cmapi.PrivateKeyAlgorithm:
			checks.String(el, path.Child(check.path), check.policy.(*string), check.request.(string))
		}
	}

	return nil
}

func evaluatex509Subject(el *field.ErrorList, path *field.Path, policy *cmpolicy.PolicyX509Subject, subject pkix.Name) []check {
	// Allow all
	if policy == nil {
		return nil
	}

	return []check{
		{"allowedOrganizations", policy.AllowedOrganizations, subject.Organization},
		{"allowedCountries", policy.AllowedCountries, subject.Country},
		{"allowedOrganizationalUnits", policy.AllowedOrganizationalUnits, subject.OrganizationalUnit},
		{"allowedLocalities", policy.AllowedLocalities, subject.Locality},
		{"allowedProvinces", policy.AllowedProvinces, subject.Province},
		{"allowedStreetAddresses", policy.AllowedStreetAddresses, subject.StreetAddress},
		{"allowedPostalCodes", policy.AllowedPostalCodes, subject.PostalCode},
		{"allowedSerialNumber", policy.AllowedSerialNumber, subject.SerialNumber},
	}
}

func evaluatePrivateKey(el *field.ErrorList, path *field.Path, policy *cmpolicy.PolicyPrivateKey, csr *x509.CertificateRequest) ([]check, error) {
	// Allow all
	if policy == nil {
		return nil, nil
	}

	alg, size, err := parsePublicKey(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	checks.MinSize(el, path.Child("minSize"), policy.MinSize, size)
	checks.MaxSize(el, path.Child("minSize"), policy.MaxSize, size)

	return []check{
		{"allowedAlgorithm", policy.AllowedAlgorithm, alg},
	}, nil
}

// parsePublicKey will return the algorithm and size of the given public key.
// If the public key cannot be decoded, returns error.
func parsePublicKey(pub interface{}) (cmapi.PrivateKeyAlgorithm, int, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		rsapub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return "", -1, parseKeyError
		}
		return cmapi.RSAKeyAlgorithm, rsapub.Size(), nil
	case *ecdsa.PublicKey:
		ecdsapub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return "", -1, parseKeyError
		}
		return cmapi.ECDSAKeyAlgorithm, ecdsapub.Curve.Params().BitSize, nil
	default:
		return "", -1, parseKeyError
	}
}
