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

package policies

type Reason interface {
	Reason() string
}

type InvalidInputReason string

var _ Reason = InvalidInputReason("")

func (r InvalidInputReason) Reason() string {
	return string(r)
}

const (
	// DoesNotExist is a policy violation reason for a scenario where
	// Certificate's spec.secretName secret does not exist.
	DoesNotExist InvalidInputReason = "DoesNotExist"
	// MissingData is a policy violation reason for a scenario where
	// Certificate's spec.secretName secret has missing data.
	MissingData InvalidInputReason = "MissingData"
	// InvalidKeyPair is a policy violation reason for a scenario where public
	// key of certificate does not match private key.
	InvalidKeyPair InvalidInputReason = "InvalidKeyPair"
	// InvalidManagedFields is a policy violation reason for a scenario where
	// managed fields on the Secret are invalid.
	InvalidManagedFields InvalidInputReason = "InvalidManagedFields"
	// InvalidPrivateKey is a policy violation reason for a scenario where the
	// private key in the Input Secret could not be parsed or decoded.
	InvalidPrivateKey InvalidInputReason = "InvalidPrivateKey"
	// InvalidCertificate is a policy violation whereby the signed certificate in
	// the Input Secret could not be parsed or decoded.
	InvalidCertificate InvalidInputReason = "InvalidCertificate"
	// InvalidCertificateRequest is a policy violation whereby the CSR in
	// the Input CertificateRequest could not be parsed or decoded.
	InvalidCertificateRequest InvalidInputReason = "InvalidCertificateRequest"
)

type IssuanceReason string

var _ Reason = IssuanceReason("")

func (r IssuanceReason) Reason() string {
	return string(r)
}

const (
	// IncorrectIssuer is a policy violation reason for a scenario where
	// Certificate has been issued by incorrect Issuer.
	IncorrectIssuer IssuanceReason = "IncorrectIssuer"
	// IncorrectCertificate is a policy violation reason for a scenario where
	// the Secret referred to by this Certificate's spec.secretName,
	// already has a `cert-manager.io/certificate-name` annotation
	// with the name of another Certificate.
	IncorrectCertificate IssuanceReason = "IncorrectCertificate"

	// SecretMismatch is a policy violation reason for a scenario where Secret's
	// private key does not match spec.
	SecretMismatch IssuanceReason = "SecretMismatch"
	// RequestChanged is a policy violation reason for a scenario where
	// CertificateRequest not valid for Certificate's spec.
	RequestChanged IssuanceReason = "RequestChanged"

	// Renewing is a policy violation reason for a scenario where
	// Certificate's renewal time is now or in past.
	Renewing IssuanceReason = "Renewing"
	// Expired is a policy violation reason for a scenario where Certificate has
	// expired.
	Expired IssuanceReason = "Expired"
)

type PostIssuanceReason string

var _ Reason = PostIssuanceReason("")

func (r PostIssuanceReason) Reason() string {
	return string(r)
}

const (
	// SecretMetadataMismatch is a policy violation whereby the Secret has
	// extra, missing, or wrong Annotations or Labels. The expected set of labels
	// and annotations are based on the Certificate's SecretTemplate and the
	// labels and annotations managed by cert-manager.
	SecretMetadataMismatch PostIssuanceReason = "SecretMetadataMismatch"
	// AdditionalOutputFormatsMismatch is a policy violation whereby the
	// Certificate's AdditionalOutputFormats is not reflected on the target
	// Secret, either by having extra, missing, or wrong values.
	AdditionalOutputFormatsMismatch PostIssuanceReason = "AdditionalOutputFormatsMismatch"
	// SecretOwnerRefMismatch is a policy violation whereby the Secret either has
	// a missing owner reference to the Certificate, or has an owner reference it
	// shouldn't have.
	SecretOwnerRefMismatch PostIssuanceReason = "SecretOwnerRefMismatch"
	// SecretKeystoreMismatch is a policy violation whereby the Secret does not have
	// the requested keystore formats.
	SecretKeystoreMismatch PostIssuanceReason = "SecretKeystoreMismatch"
)

type MaybeReason[T Reason] struct {
	invalidInput InvalidInputReason
	validInput   T
}

var _ Reason = MaybeReason[IssuanceReason]{}
var _ Reason = MaybeReason[PostIssuanceReason]{}

func (r MaybeReason[T]) Reason() string {
	if r.invalidInput != "" {
		return r.invalidInput.Reason()
	}
	return r.validInput.Reason()
}

func (r MaybeReason[T]) String() string {
	return r.Reason()
}
