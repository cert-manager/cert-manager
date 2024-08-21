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

// Package policies provides functionality to evaluate Certificate's state
package policies

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
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
	// Deprecated: This field should not be used in any policy checks. It is
	// only used in the gatherer package.
	// TODO: remove this field
	NextRevisionRequest *cmapi.CertificateRequest
}

// A Func evaluates the given input data and decides whether a check has passed
// or failed, returning additional human readable information in the 'reason'
// and 'message' return parameters if so.
// TODO: refactor code and rename this type to Policy
type Func func(Input) (reason, message string, failed bool)

type Policy[T any] func(Input) T

// A Chain of PolicyFuncs to be evaluated in order.
// TODO: refactor code and remove this type in favor of the Policy type
type Chain Policy[*Violation[Reason]]

func NewChain[R Reason](fns ...Policy[*Violation[R]]) Chain {
	return func(input Input) *Violation[Reason] {
		violation := firstFailure(fns...)(input)
		if violation != nil {
			return &Violation[Reason]{
				Reason:  violation.Reason,
				Message: violation.Message,
			}
		}
		return nil
	}
}

// Evaluate will evaluate the entire policy chain using the provided input.
// As soon as it is discovered that the input violates one policy,
// Evaluate will return and not evaluate the rest of the chain.
func (c Chain) Evaluate(input Input) (string, string, bool) {
	violation := c(input)
	if violation != nil {
		return violation.Reason.Reason(), violation.Message, true
	}
	return "", "", false
}

func firstFailure[R Reason](fns ...Policy[*Violation[R]]) Policy[*Violation[R]] {
	return func(input Input) *Violation[R] {
		for _, fn := range fns {
			violation := fn(input)
			if violation != nil {
				return violation
			}
		}
		return nil
	}
}

func prefixFailureMessage[R Reason](prefix string, fns ...Policy[*Violation[R]]) Policy[*Violation[R]] {
	return func(input Input) *Violation[R] {
		violation := firstFailure(fns...)(input)
		if violation != nil {
			return &Violation[R]{
				Reason:  violation.Reason,
				Message: prefix + violation.Message,
			}
		}
		return nil
	}
}

// NewReadinessPolicyChain includes readiness policy checks, which if return
// true, would cause a Certificate to be marked as not ready.
//
// If this chain returns true, the status of the Certificate resource will show
// NotReady.
func NewReadinessPolicyChain(c clock.Clock) Chain {
	return NewChain(prefixFailureMessage(
		"Certificate is not Ready because ",

		readinessChecks(c),
	))
}

func readinessChecks(c clock.Clock) Policy[*Violation[MaybeReason[IssuanceReason]]] {
	return func(i Input) *Violation[MaybeReason[IssuanceReason]] {
		if validation := firstFailure(
			// Make sure that the tls Secret exists and contains a valid certificate and private key
			SecretDoesNotExist,                                  // Make sure the Secret exists
			SecretIsMissingData,                                 // Make sure the Secret has the required keys set
			SecretContainsInvalidData,                           // Make sure the Secret contains a valid private key and certificate
			SecretPublicPrivateKeysNotMatching,                  // Make sure the PrivateKey and PublicKey match in the Secret
			SecretPublicKeyDiffersFromCurrentCertificateRequest, // Make sure the Secret's PublicKey matches the current CertificateRequest
		)(i); validation != nil {
			return MaybeValidation[IssuanceReason](validation)
		}

		return firstFailure(
			// Make sure the Secret was issued for the same Issuer
			SecretIssuerAnnotationsMismatch, // Make sure the Secret's IssuerRef annotations match the Certificate spec

			// Make sure the Secret was issued for the same Certificate spec
			SecretPrivateKeyMismatchesSpec,          // Make sure the PrivateKey Type and Size match the Certificate spec
			CurrentCertificateRequestMismatchesSpec, // Make sure the current CertificateRequest matches the Certificate spec

			// Make sure the Certificate in the Secret has not expired
			CurrentCertificateHasExpired(c), // Make sure the Certificate in the Secret has not expired
		)(i)
	}
}

// NewTriggerPolicyChain includes trigger policy checks, which if return true,
// should cause a Certificate to be marked for issuance.
//
// If this chain returns true, a new certificate will be issued.
// This chain should include all checks that are in the readiness chain, as well
// as additional checks that proactively trigger re-issuance before the
// certificate is marked as not ready.
func NewTriggerPolicyChain(c clock.Clock) Chain {
	return NewChain(prefixFailureMessage(
		"Issuing certificate because ",

		readinessChecks(c),                 // Include all readiness checks
		CurrentCertificateNearingExpiry(c), // Make sure the Certificate in the Secret is not nearing expiry
	))
}

// NewSecretPostIssuancePolicyChain includes policy checks that are to be
// performed _after_ issuance has been successful, testing for the presence and
// correctness of metadata and output formats of Certificate's Secrets.
//
// If this chain returns true, the Secret will be updated without having to
// re-issue the certificate.
func NewSecretPostIssuancePolicyChain(ownerRefEnabled bool, fieldManager string) Chain {
	// NOTE: for the checks below, we use the managed fields of the Secret to
	// determine what fields in the Secret are managed by cert-manager. This
	// allows us to ignore fields that are not managed by cert-manager, and
	// only update the Secret if the fields we manage are incorrect, missing
	// or no longer required.
	return NewChain(prefixFailureMessage(
		"Updating Secret because ",

		// Make sure the Secret has the correct labels and annotations, these are a
		// combination of cert-manager managed labels and annotations, and the labels
		// and annotations configured in the Certificate spec.
		SecretBaseLabelsMismatch,
		SecretCertificateDetailsAnnotationsMismatch,
		SecretSecretTemplateMismatch,
		SecretLabelsAndAnnotationsManagedFieldsMismatch(fieldManager),

		// Make sure the Secret has the correct additional output formats.
		SecretAdditionalOutputFormatsMismatch,
		SecretAdditionalOutputFormatsManagedFieldsMismatch(fieldManager),

		// Make sure the Secret has the correct owner references.
		SecretOwnerReferenceMismatch(ownerRefEnabled),
		SecretOwnerReferenceManagedFieldMismatch(ownerRefEnabled, fieldManager),

		// Make sure the Secret has the correct keystore format.
		SecretKeystoreFormatMismatch,
	))
}

// NewTemporaryCertificatePolicyChain includes policy checks for ensuing a
// temporary certificate is valid.
func NewTemporaryCertificatePolicyChain() Chain {
	return NewChain(prefixFailureMessage(
		"Generating temporary certificate because ",

		// Make sure that the tls Secret exists and contains a valid certificate and private key
		SecretDoesNotExist,                 // Make sure the Secret exists
		SecretIsMissingData,                // Make sure the Secret has the required keys set
		SecretContainsInvalidData,          // Make sure the Secret contains a valid private key and certificate
		SecretPublicPrivateKeysNotMatching, // Make sure the PrivateKey and PublicKey match in the Secret
	))
}
