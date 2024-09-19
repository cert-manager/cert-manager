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
	NextRevisionRequest *cmapi.CertificateRequest
}

// A Func evaluates the given input data and decides whether a check has passed
// or failed, returning additional human readable information in the 'reason'
// and 'message' return parameters if so.
type Func func(Input) (reason, message string, failed bool)

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

// NewTriggerPolicyChain includes trigger policy checks, which if returns true,
// should cause a Certificate to be marked for issuance.
func NewTriggerPolicyChain(c clock.Clock) Chain {
	return Chain{
		SecretDoesNotExist,     // Make sure the Secret exists
		SecretIsMissingData,    // Make sure the Secret has the required keys set
		SecretPublicKeysDiffer, // Make sure the PrivateKey and PublicKey match in the Secret

		SecretIssuerAnnotationsMismatch,          // Make sure the Secret's IssuerRef annotations match the Certificate spec
		SecretCertificateNameAnnotationsMismatch, // Make sure the Secret's CertificateName annotation matches the Certificate's name

		SecretPrivateKeyMismatchesSpec,                      // Make sure the PrivateKey Type and Size match the Certificate spec
		SecretPublicKeyDiffersFromCurrentCertificateRequest, // Make sure the Secret's PublicKey matches the current CertificateRequest
		CurrentCertificateRequestMismatchesSpec,             // Make sure the current CertificateRequest matches the Certificate spec
		CurrentCertificateNearingExpiry(c),                  // Make sure the Certificate in the Secret is not nearing expiry
	}
}

// NewReadinessPolicyChain includes readiness policy checks, which if returns
// true, would cause a Certificate to be marked as not ready.
func NewReadinessPolicyChain(c clock.Clock) Chain {
	return Chain{
		SecretDoesNotExist,     // Make sure the Secret exists
		SecretIsMissingData,    // Make sure the Secret has the required keys set
		SecretPublicKeysDiffer, // Make sure the PrivateKey and PublicKey match in the Secret

		SecretIssuerAnnotationsMismatch,          // Make sure the Secret's IssuerRef annotations match the Certificate spec
		SecretCertificateNameAnnotationsMismatch, // Make sure the Secret's CertificateName annotation matches the Certificate's name

		SecretPrivateKeyMismatchesSpec,                      // Make sure the PrivateKey Type and Size match the Certificate spec
		SecretPublicKeyDiffersFromCurrentCertificateRequest, // Make sure the Secret's PublicKey matches the current CertificateRequest
		CurrentCertificateRequestMismatchesSpec,             // Make sure the current CertificateRequest matches the Certificate spec
		CurrentCertificateHasExpired(c),                     // Make sure the Certificate in the Secret has not expired
	}
}

// NewSecretPostIssuancePolicyChain includes policy checks that are to be
// performed _after_ issuance has been successful, testing for the presence and
// correctness of metadata and output formats of Certificate's Secrets.
func NewSecretPostIssuancePolicyChain(ownerRefEnabled bool, fieldManager string) Chain {
	return Chain{
		SecretBaseLabelsMismatch,                                             // Make sure the managed labels have the correct values
		SecretCertificateDetailsAnnotationsMismatch,                          // Make sure the managed certificate details annotations have the correct values
		SecretManagedLabelsAndAnnotationsManagedFieldsMismatch(fieldManager), // Make sure only the expected managed labels and annotations exist
		SecretSecretTemplateMismatch,                                         // Make sure the template label and annotation values match the secret
		SecretSecretTemplateManagedFieldsMismatch(fieldManager),              // Make sure only the expected template labels and annotations exist
		SecretAdditionalOutputFormatsMismatch,
		SecretAdditionalOutputFormatsManagedFieldsMismatch(fieldManager),
		SecretOwnerReferenceMismatch(ownerRefEnabled),
		SecretOwnerReferenceManagedFieldMismatch(ownerRefEnabled, fieldManager),

		SecretKeystoreFormatMismatch,
	}
}

// NewTemporaryCertificatePolicyChain includes policy checks for ensuing a
// temporary certificate is valid.
func NewTemporaryCertificatePolicyChain() Chain {
	return Chain{
		SecretDoesNotExist,     // Make sure the Secret exists
		SecretIsMissingData,    // Make sure the Secret has the required keys set
		SecretPublicKeysDiffer, // Make sure the PrivateKey and PublicKey match in the Secret
	}
}
