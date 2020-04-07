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

package trigger

import (
	"crypto/tls"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	certificates "github.com/jetstack/cert-manager/pkg/controller/expcertificates"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// evaluatePolicyChain calls each provided policy function in order using the
// provided input.
// If any of the policies return reissue=true, it will immediately return with
// the results of the call.
func evaluatePolicyChain(input policyInput, policies ...triggerPolicyFunc) (string, string, bool) {
	for _, policyFunc := range policies {
		reason, message, reissue := policyFunc(input)
		if reissue {
			return reason, message, reissue
		}
	}
	return "", "", false
}

type policyInput struct {
	certificate            *cmapi.Certificate
	currentRevisionRequest *cmapi.CertificateRequest
	secret                 *corev1.Secret
}

type triggerPolicyFunc func(policyInput) (reason, message string, reissue bool)

var defaultPolicyChain = []triggerPolicyFunc{
	secretDoesNotExistPolicy,
	secretHasDataPolicy,
	secretPublicKeysMatch,
	secretHasUpToDateIssuerAnnotations,
	currentCertificateRequestValidForSpec,
	currentCertificateNearingExpiry,
	// TODO: add policy check that ensures the requested spec.privateKey
	//  matches the private key for the currently issued Secret.
	//  If any options have changed, including just the `keyFormat` field,
	//  a re-issuance will be triggered.
}

func secretDoesNotExistPolicy(input policyInput) (string, string, bool) {
	if input.secret == nil {
		return "DoesNotExist", "Issuing certificate as Secret does not exist", true
	}
	return "", "", false
}

func secretHasDataPolicy(input policyInput) (string, string, bool) {
	if input.secret.Data == nil {
		return "MissingData", "Issuing certificate as Secret does not contain any data", true
	}
	pkData := input.secret.Data[corev1.TLSPrivateKeyKey]
	certData := input.secret.Data[corev1.TLSCertKey]
	if len(pkData) == 0 {
		return "MissingData", "Issuing certificate as Secret does not contain a private key", true
	}
	if len(certData) == 0 {
		return "MissingData", "Issuing certificate as Secret does not contain a certificate", true
	}
	return "", "", false
}

func secretPublicKeysMatch(input policyInput) (string, string, bool) {
	pkData := input.secret.Data[corev1.TLSPrivateKeyKey]
	certData := input.secret.Data[corev1.TLSCertKey]
	// TODO: replace this with a generic decoder that can handle different
	//  formats such as JKS, P12 etc (i.e. add proper support for keystores)
	_, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return "InvalidKeyPair", fmt.Sprintf("Issuing certificate as Secret contains an invalid key-pair: %v", err), true
	}
	return "", "", false
}

func secretHasUpToDateIssuerAnnotations(input policyInput) (string, string, bool) {
	name := input.secret.Annotations[cmapi.IssuerNameAnnotationKey]
	kind := input.secret.Annotations[cmapi.IssuerKindAnnotationKey]
	group := input.secret.Annotations[cmapi.IssuerGroupAnnotationKey]
	if name != input.certificate.Spec.IssuerRef.Name ||
		!issuerKindsEqual(kind, input.certificate.Spec.IssuerRef.Kind) ||
		!issuerGroupsEqual(group, input.certificate.Spec.IssuerRef.Group) {
		return "IncorrectIssuer", fmt.Sprintf("Issuing certificate as Secret was previously issued by %s", formatIssuerRef(name, kind, group)), true
	}
	return "", "", false
}

func currentCertificateRequestValidForSpec(input policyInput) (string, string, bool) {
	if input.currentRevisionRequest == nil {
		// Fallback to comparing the Certificate spec with the issued certificate.
		// This case is encountered if the CertificateRequest that issued the current
		// Secret is not available (most likely due to it being deleted).
		// This comparison is a lot less robust than comparing against the CertificateRequest
		// as it has to tolerate/permit certain fields being overridden or ignored by the
		// signer/issuer implementation.
		return currentSecretValidForSpec(input)
	}

	violations, err := certificates.RequestMatchesSpec(input.currentRevisionRequest, input.certificate.Spec)
	if err != nil {
		// If parsing the request fails, we don't immediately trigger a re-issuance as
		// the existing certificate stored in the Secret may still be valid/up to date.
		return "", "", false
	}
	if len(violations) > 0 {
		return "RequestChanged", fmt.Sprintf("Fields on existing CertificateRequest resource not up to date: %v", violations), true
	}

	return "", "", false
}

// currentSecretValidForSpec is not actually registered as part of the policy chain
// and is instead called by currentCertificateRequestValidForSpec if no there
// is no existing CertificateRequest resource.
func currentSecretValidForSpec(input policyInput) (string, string, bool) {
	violations, err := certificates.SecretDataAltNamesMatchSpec(input.secret, input.certificate.Spec)
	if err != nil {
		// This case should never be reached as we already check the certificate data can
		// be parsed in an earlier policy check, but handle it anyway.
		// TODO: log a message
		return "", "", false
	}

	if len(violations) > 0 {
		return "SecretMismatch", fmt.Sprintf("Existing issued Secret is not up to date for spec: %v", violations), true
	}

	return "", "", false
}

func currentCertificateNearingExpiry(input policyInput) (string, string, bool) {
	certData := input.secret.Data[corev1.TLSCertKey]
	// TODO: replace this with a generic decoder that can handle different
	//  formats such as JKS, P12 etc (i.e. add proper support for keystores)
	cert, err := pki.DecodeX509CertificateBytes(certData)
	if err != nil {
		// This case should never happen as it should always be caught by the
		// secretPublicKeysMatch function beforehand, but handle it just in case.
		return "InvalidCertificate", fmt.Sprintf("Failed to decode stored certificate: %v", err), true
	}

	renewBefore := cmapi.DefaultRenewBefore
	if input.certificate.Spec.RenewBefore != nil {
		renewBefore = input.certificate.Spec.RenewBefore.Duration
	}
	actualDuration := cert.NotAfter.Sub(cert.NotBefore)
	if renewBefore > actualDuration {
		renewBefore = actualDuration / 3
	}
	renewAfter := cert.NotAfter.Add(-1 * renewBefore)
	if time.Now().After(renewAfter) {
		return "Renewing", fmt.Sprintf("Renewing certificate as current certificate is within %s of expiry", renewBefore), true
	}
	return "", "", false
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
