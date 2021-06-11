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

//Package policies provides functionality to evaluate Certificate's state
package policies

import (
	"crypto/tls"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificates"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Input struct {
	Certificate *cmapi.Certificate
	Secret      *corev1.Secret

	// The "current" certificate request designates the certificate request that
	// led to the current revision of the certificate. The "current" certificate
	// request is by definition in a ready state, and can be seen as the source
	// of information of the current certificate. Take a look at the gatherer
	// package's documentation to see more about why we care about the "current"
	// certificate request.
	CurrentRevisionRequest *cmapi.CertificateRequest

	// The "next" certificate request is the one that is currently being issued.
	// Take a look at the gatherer package's documentation to see more about why
	// we care about the "next" certificate request.
	NextRevisionRequest *cmapi.CertificateRequest
}

// A Func evaluates the given input data and decides whether a
// re-issuance is required, returning additional human readable information
// in the 'reason' and 'message' return parameters if so.
type Func func(Input) (reason, message string, reissue bool)

// A Chain of PolicyFuncs to be evaluated in order.
type Chain []Func

// Evaluate will evaluate the entire policy chain using the provided input.
// As soon as it is discovered that the input violates one policy,
// Evaluate will return and not evaluate the rest of the chain.
func (c Chain) Evaluate(input Input) (string, string, bool) {
	for _, policyFunc := range c {
		reason, message, violationFound := policyFunc(input)
		if violationFound {
			return reason, message, violationFound
		}
	}
	return "", "", false
}

func NewTriggerPolicyChain(c clock.Clock) Chain {
	return Chain{
		SecretDoesNotExist,
		SecretIsMissingData,
		SecretPublicKeysDiffer,
		SecretPrivateKeyMatchesSpec,
		SecretIssuerAnnotationsNotUpToDate,
		CurrentCertificateRequestNotValidForSpec,
		CurrentCertificateNearingExpiry(c),
	}
}

func SecretDoesNotExist(input Input) (string, string, bool) {
	if input.Secret == nil {
		return DoesNotExist, "Issuing certificate as Secret does not exist", true
	}
	return "", "", false
}

func SecretIsMissingData(input Input) (string, string, bool) {
	if input.Secret.Data == nil {
		return MissingData, "Issuing certificate as Secret does not contain any data", true
	}
	pkData := input.Secret.Data[corev1.TLSPrivateKeyKey]
	certData := input.Secret.Data[corev1.TLSCertKey]
	if len(pkData) == 0 {
		return MissingData, "Issuing certificate as Secret does not contain a private key", true
	}
	if len(certData) == 0 {
		return MissingData, "Issuing certificate as Secret does not contain a certificate", true
	}
	return "", "", false
}

func SecretPublicKeysDiffer(input Input) (string, string, bool) {
	pkData := input.Secret.Data[corev1.TLSPrivateKeyKey]
	certData := input.Secret.Data[corev1.TLSCertKey]
	// TODO: replace this with a generic decoder that can handle different
	//  formats such as JKS, P12 etc (i.e. add proper support for keystores)
	_, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return InvalidKeyPair, fmt.Sprintf("Issuing certificate as Secret contains an invalid key-pair: %v", err), true
	}
	return "", "", false
}

func SecretPrivateKeyMatchesSpec(input Input) (string, string, bool) {
	if input.Secret.Data == nil || len(input.Secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		return SecretMismatch, "Existing issued Secret does not contain private key data", true
	}

	pkBytes := input.Secret.Data[corev1.TLSPrivateKeyKey]
	pk, err := pki.DecodePrivateKeyBytes(pkBytes)
	if err != nil {
		return SecretMismatch, fmt.Sprintf("Existing issued Secret contains invalid private key data: %v", err), true
	}

	violations, err := certificates.PrivateKeyMatchesSpec(pk, input.Certificate.Spec)
	if err != nil {
		return SecretMismatch, fmt.Sprintf("Failed to check private key is up to date: %v", err), true
	}
	if len(violations) > 0 {
		return SecretMismatch, fmt.Sprintf("Existing private key is not up to date for spec: %v", violations), true
	}
	return "", "", false
}

func SecretIssuerAnnotationsNotUpToDate(input Input) (string, string, bool) {
	name := input.Secret.Annotations[cmapi.IssuerNameAnnotationKey]
	kind := input.Secret.Annotations[cmapi.IssuerKindAnnotationKey]
	group := input.Secret.Annotations[cmapi.IssuerGroupAnnotationKey]
	if name != input.Certificate.Spec.IssuerRef.Name ||
		!issuerKindsEqual(kind, input.Certificate.Spec.IssuerRef.Kind) ||
		!issuerGroupsEqual(group, input.Certificate.Spec.IssuerRef.Group) {
		return IncorrectIssuer, fmt.Sprintf("Issuing certificate as Secret was previously issued by %s", formatIssuerRef(name, kind, group)), true
	}
	return "", "", false
}

func CurrentCertificateRequestNotValidForSpec(input Input) (string, string, bool) {
	if input.CurrentRevisionRequest == nil {
		// Fallback to comparing the Certificate spec with the issued certificate.
		// This case is encountered if the CertificateRequest that issued the current
		// Secret is not available (most likely due to it being deleted).
		// This comparison is a lot less robust than comparing against the CertificateRequest
		// as it has to tolerate/permit certain fields being overridden or ignored by the
		// signer/issuer implementation.
		return currentSecretValidForSpec(input)
	}

	violations, err := certificates.RequestMatchesSpec(input.CurrentRevisionRequest, input.Certificate.Spec)
	if err != nil {
		// If parsing the request fails, we don't immediately trigger a re-issuance as
		// the existing certificate stored in the Secret may still be valid/up to date.
		return "", "", false
	}
	if len(violations) > 0 {
		return RequestChanged, fmt.Sprintf("Fields on existing CertificateRequest resource not up to date: %v", violations), true
	}

	return "", "", false
}

// currentSecretValidForSpec is not actually registered as part of the policy chain
// and is instead called by currentCertificateRequestValidForSpec if no there
// is no existing CertificateRequest resource.
func currentSecretValidForSpec(input Input) (string, string, bool) {
	violations, err := certificates.SecretDataAltNamesMatchSpec(input.Secret, input.Certificate.Spec)
	if err != nil {
		// This case should never be reached as we already check the certificate data can
		// be parsed in an earlier policy check, but handle it anyway.
		// TODO: log a message
		return "", "", false
	}

	if len(violations) > 0 {
		return SecretMismatch, fmt.Sprintf("Existing issued Secret is not up to date for spec: %v", violations), true
	}

	return "", "", false
}

// CurrentCertificateNearingExpiry returns a policy function that can be used to
// check whether an X.509 cert currently issued for a Certificate should be
// renewed.
func CurrentCertificateNearingExpiry(c clock.Clock) Func {

	return func(input Input) (string, string, bool) {

		// Determine if the certificate is nearing expiry solely by looking at
		// the actual cert, if it exists. We assume that at this point we have
		// called policy functions that check that input.Secret and
		// input.Secret.Data exists (SecretDoesNotExist and SecretIsMissingData).
		x509cert, err := pki.DecodeX509CertificateBytes(input.Secret.Data[corev1.TLSCertKey])
		if err != nil {
			// This case should never happen as it should always be caught by the
			// secretPublicKeysMatch function beforehand, but handle it just in case.
			return "InvalidCertificate", fmt.Sprintf("Failed to decode stored certificate: %v", err), true
		}

		notBefore := metav1.NewTime(x509cert.NotBefore)
		notAfter := metav1.NewTime(x509cert.NotAfter)
		crt := input.Certificate
		renewalTime := certificates.RenewalTime(notBefore.Time, notAfter.Time, crt.Spec.RenewBefore)

		renewIn := renewalTime.Time.Sub(c.Now())
		if renewIn > 0 {
			//renewal time is in future, no need to renew
			return "", "", false
		}

		return Renewing, fmt.Sprintf("Renewing certificate as renewal was scheduled at %s", input.Certificate.Status.RenewalTime), true
	}
}

// CurrentCertificateHasExpired is used exclusively to check if the current
// issued certificate has actually expired rather than just nearing expiry.
func CurrentCertificateHasExpired(c clock.Clock) Func {
	return func(input Input) (string, string, bool) {
		certData, ok := input.Secret.Data[corev1.TLSCertKey]
		if !ok {
			return MissingData, "Missing Certificate data", true
		}
		// TODO: replace this with a generic decoder that can handle different
		//  formats such as JKS, P12 etc (i.e. add proper support for keystores)
		cert, err := pki.DecodeX509CertificateBytes(certData)
		if err != nil {
			// This case should never happen as it should always be caught by the
			// secretPublicKeysMatch function beforehand, but handle it just in case.
			return "InvalidCertificate", fmt.Sprintf("Failed to decode stored certificate: %v", err), true
		}

		if c.Now().After(cert.NotAfter) {
			return Expired, fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC1123)), true
		}
		return "", "", false
	}
}

func formatIssuerRef(name, kind, group string) string {
	if group == "" {
		group = "cert-manager.io"
	}
	if kind == "" {
		kind = "Issuer"
	}
	return fmt.Sprintf("%s.%s/%s", kind, group, name)
}

const defaultIssuerKind = "Issuer"
const defaultIssuerGroup = "cert-manager.io"

func issuerKindsEqual(l, r string) bool {
	if l == "" {
		l = defaultIssuerKind
	}
	if r == "" {
		r = defaultIssuerKind
	}
	return l == r
}

func issuerGroupsEqual(l, r string) bool {
	if l == "" {
		l = defaultIssuerGroup
	}
	if r == "" {
		r = defaultIssuerGroup
	}
	return l == r
}
